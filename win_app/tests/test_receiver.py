import socket
import threading
import time
import unittest
from unittest import mock

import input_injector
import protocol
import receiver
from app_config import Config
from receiver import ReceiverServer, ServerState, handle_message

from return_edge import Rect
from fakes import FakeClipboard, FakeDesktop, FakeInjector, connected_socket_pair, wait_for_calls, wait_for_status


FAKE_PNG = protocol.PNG_SIGNATURE + b"\x00" * 64


def make_config(port=0, token="shared-token"):
    return Config(host="127.0.0.1", port=port, auth_token=token)


class ReceiverHandshakeTests(unittest.TestCase):
    def _serve(self, client_token="shared-token", **server_kwargs):
        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), **server_kwargs)
        client, connection, address = connected_socket_pair(token=client_token)
        stop_event = threading.Event()
        # _session_thread, not _handle_client: it closes the socket when the
        # handler returns, which is what a rejected client actually sees.
        thread = threading.Thread(
            target=server._session_thread,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        self.addCleanup(connection.close)
        self.addCleanup(thread.join, 1)
        self.addCleanup(stop_event.set)
        self.addCleanup(client.close)
        return statuses, client, thread

    def test_hello_receives_welcome_and_reports_connected(self):
        statuses, client, thread = self._serve()
        client.send(protocol.hello_msg())
        self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
        # The welcome is sent before the status callback fires on the
        # session thread, so poll rather than assert immediately.
        _, detail = wait_for_status(statuses, ServerState.CONNECTED)
        self.assertEqual(detail, "Connected to 127.0.0.1")

    def test_the_welcome_declares_the_role_this_receiver_is_configured_as(self):
        # This host is Windows, so a receiver set up as the Mac answering
        # "windows" is the bug itself: the peer would then map its modifiers
        # the wrong way for a Mac it is not talking to.
        statuses, client, thread = self._serve(self_target="mac", peer_target="windows")
        client.send(protocol.hello_msg())
        self.assertEqual(client.recv(), protocol.welcome_msg(platform="mac"))

    def test_the_hello_platform_reaches_the_peer_callback(self):
        seen = []
        arrived = threading.Event()

        def peer_callback(*args):
            seen.append(args)
            arrived.set()

        statuses, client, thread = self._serve(peer_callback=peer_callback)
        client.send(protocol.hello_msg(platform="windows", return_edge="left", resistance_px=40))
        self.assertTrue(arrived.wait(2.0), "the peer callback never fired")
        self.assertEqual(seen[0][1:], ("left", 40, "windows"))

    def test_a_hello_that_names_no_platform_is_read_as_this_receivers_own_role(self):
        seen = []
        arrived = threading.Event()

        def peer_callback(*args):
            seen.append(args)
            arrived.set()

        statuses, client, thread = self._serve(peer_callback=peer_callback)
        client.send(protocol.hello_msg())
        self.assertTrue(arrived.wait(2.0), "the peer callback never fired")
        self.assertEqual(seen[0][3], "windows")

    def test_a_silent_peer_at_a_mac_role_receiver_is_read_as_a_mac(self):
        seen = []
        arrived = threading.Event()

        def peer_callback(*args):
            seen.append(args)
            arrived.set()

        statuses, client, thread = self._serve(
            peer_callback=peer_callback, self_target="mac", peer_target="windows"
        )
        client.send(protocol.hello_msg())
        self.assertTrue(arrived.wait(2.0), "the peer callback never fired")
        self.assertEqual(seen[0][3], "mac")

    def test_a_declared_platform_beats_this_receivers_own_role(self):
        seen = []
        arrived = threading.Event()

        def peer_callback(*args):
            seen.append(args)
            arrived.set()

        statuses, client, thread = self._serve(peer_callback=peer_callback, self_target="mac")
        client.send(protocol.hello_msg(platform="windows"))
        self.assertTrue(arrived.wait(2.0), "the peer callback never fired")
        self.assertEqual(seen[0][3], "windows")

    def test_wrong_token_is_closed_without_a_reply(self):
        statuses, client, thread = self._serve(client_token="not-the-token")
        client.send(protocol.hello_msg())
        client.settimeout(2.0)
        with self.assertRaises(protocol.ConnectionClosed):
            client.recv()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertNotIn(ServerState.CONNECTED, [state for state, _ in statuses])

    def test_replayed_frame_drops_the_connection(self):
        statuses, client, thread = self._serve()
        client.send(protocol.hello_msg())
        self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
        frame = client.session.seal(protocol.ping_msg())
        client.sock.sendall(frame)
        client.sock.sendall(frame)
        client.settimeout(2.0)
        with self.assertRaises(protocol.ConnectionClosed):
            while True:
                client.recv()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())

    def test_hello_without_version_is_rejected_with_welcome_error(self):
        statuses, client, thread = self._serve()
        client.send({"type": protocol.MSG_HELLO, "data": {}})
        reply = client.recv()
        self.assertEqual(reply["type"], protocol.MSG_WELCOME)
        self.assertEqual(reply["data"].get("error"), "version_mismatch")
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertNotIn(ServerState.CONNECTED, [state for state, _ in statuses])
        self.assertIn(
            (ServerState.ERROR, "Mac app is an older Beamer version — update both apps"),
            statuses,
        )

    def test_unsupported_version_is_rejected_with_welcome_error(self):
        statuses, client, thread = self._serve()
        client.send({"type": protocol.MSG_HELLO, "data": {"version": 1}})
        self.assertEqual(client.recv(), protocol.welcome_msg(error="version_mismatch"))
        self.assertNotIn(ServerState.CONNECTED, [state for state, _ in statuses])

    def test_pre_v4_client_gets_a_cleartext_version_mismatch(self):
        # A v3 Mac opens with a length-prefixed cleartext hello, no preamble.
        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        raw = socket.create_connection(listener.getsockname())
        connection, address = listener.accept()
        listener.close()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            raw.sendall(protocol.legacy_frame({"type": protocol.MSG_HELLO, "data": {"token": "shared-token", "version": 3}}))
            raw.settimeout(2.0)
            expected = protocol.legacy_frame(protocol.welcome_msg(error="version_mismatch"))
            got = b""
            while len(got) < len(expected):
                chunk = raw.recv(4096)
                if not chunk:
                    break
                got += chunk
            self.assertEqual(got, expected)
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertIn(
                (ServerState.ERROR, "Mac app is an older Beamer version — update both apps"),
                statuses,
            )
        finally:
            raw.close()
            stop_event.set()
            thread.join(timeout=1)
            connection.close()

    def test_other_wire_version_is_answered_with_our_preamble_and_closed(self):
        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        raw = socket.create_connection(listener.getsockname())
        connection, address = listener.accept()
        listener.close()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._session_thread,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            raw.sendall(protocol.WIRE_MAGIC + bytes([protocol.PROTOCOL_VERSION + 1]) + b"\x01" * protocol.NONCE_PREFIX_SIZE)
            raw.settimeout(2.0)
            got = raw.recv(protocol.PREAMBLE_SIZE)
            self.assertEqual(got[: len(protocol.WIRE_MAGIC) + 1], protocol.WIRE_MAGIC + bytes([protocol.PROTOCOL_VERSION]))
            self.assertEqual(raw.recv(4096), b"")
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertIn(
                (ServerState.ERROR, f"Mac app is Beamer protocol v{protocol.PROTOCOL_VERSION + 1}, this PC is v{protocol.PROTOCOL_VERSION} — update both apps"),
                statuses,
            )
        finally:
            raw.close()
            stop_event.set()
            thread.join(timeout=1)
            connection.close()


class ReceiverPreemptionTests(unittest.TestCase):
    # This test used to shorten SESSION_READ_TIMEOUT_SECONDS to 0.3s for the
    # whole test, on the theory that a short read timeout is the
    # deterministic backstop bounding how long a preempted session can take
    # to notice it was superseded. Two separate timing problems made that
    # ~1-in-8 flaky, both now fixed below:
    #
    # 1. That backstop starts counting down from the moment A authenticates,
    #    independent of anything B does. On a slow/loaded run, A's *own*
    #    silence could trip the shortened timeout before B ever finished
    #    connecting, making the server legitimately (but spuriously, for this
    #    test's purposes) report WAITING before the handover even started.
    #    Fixed by resetting A's idle clock at a point the test controls,
    #    immediately before connecting B: a `ping` is a real message, so
    #    receiving it makes thread_a's blocked recv() return and loop back
    #    into a fresh recv() call with a fresh timeout window, decoupling the
    #    deadline from whatever setup work (A's own authentication,
    #    wait_for_status, ...) came before it.
    #
    # 2. Closing a socket from a different thread than the one blocked in
    #    recv() on it doesn't reliably interrupt that recv() on macOS --
    #    confirmed empirically (a throwaway probe: ~20-40% of trials left the
    #    blocked thread stuck until its full configured read timeout
    #    elapsed, unmoved by another thread's shutdown()+close() of the same
    #    fd). So thread_a's own recv() may not notice the server's
    #    preemption-driven close of connection_a promptly, and nothing the
    #    test can do from the client side afterwards wakes a recv() already
    #    blocked on an fd the server has *already fully closed* -- there is
    #    no live socket left to deliver anything to. thread_a's own
    #    (shortened) read timeout is the only way it reliably exits in that
    #    unlucky case, which means the test's own wait for thread_a to join
    #    can itself take up to that same short timeout. B's *own* idle
    #    detection must not have a chance to fire for real during that wait
    #    -- it would legitimately (B really has gone quiet) but spuriously
    #    (for this test) report WAITING too. Fixed by giving B, once
    #    connected, a read timeout far larger than anything this test could
    #    take: B's own liveness detection isn't what's under test here, only
    #    that its status doesn't flap while A is being torn down.
    _READ_TIMEOUT_SECONDS = 0.4
    _B_READ_TIMEOUT_SECONDS = 30.0

    def test_new_authenticated_client_preempts_the_previous_one_without_flapping_status(self):
        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        config = make_config()
        stop_event = threading.Event()

        with mock.patch.object(receiver, "SESSION_READ_TIMEOUT_SECONDS", self._READ_TIMEOUT_SECONDS):
            client_a, connection_a, address_a = connected_socket_pair()
            thread_a = threading.Thread(
                target=server._handle_client,
                args=(connection_a, address_a, config, stop_event),
            )
            thread_a.start()
            client_a.send(protocol.hello_msg())
            self.assertEqual(client_a.recv(), protocol.welcome_msg(platform="windows"))
            wait_for_status(statuses, ServerState.CONNECTED)

        client_b = connection_b = thread_b = None
        try:
            # Reset A's idle clock right here, at a moment the test controls,
            # so its (still short, unpatched-again-below) read timeout races
            # only the setup immediately following (fast, local, and
            # bounded) rather than everything before it.
            with mock.patch.object(receiver, "SESSION_READ_TIMEOUT_SECONDS", self._READ_TIMEOUT_SECONDS):
                client_a.send(protocol.ping_msg())

            # B gets a generously long read timeout (see the class docstring)
            # so its own idle detection can't fire for real while the test
            # waits out thread_a's worst case below. Kept in effect for the
            # rest of the test, since thread_b reads this constant once, the
            # first time it calls connection.settimeout(...).
            with mock.patch.object(receiver, "SESSION_READ_TIMEOUT_SECONDS", self._B_READ_TIMEOUT_SECONDS):
                client_b, connection_b, address_b = connected_socket_pair()
                thread_b = threading.Thread(
                    target=server._handle_client,
                    args=(connection_b, address_b, config, stop_event),
                )
                thread_b.start()
                client_b.send(protocol.hello_msg())
                self.assertEqual(client_b.recv(), protocol.welcome_msg(platform="windows"))

                # A must be severed once B takes over. This is a real,
                # server-initiated shutdown()+close() of connection_a, which
                # reliably delivers a FIN to client_a's end of an actual TCP
                # connection -- unlike interrupting thread_a's own blocked
                # recv() from another thread (see the class docstring above),
                # a peer-visible EOF over an actual socket is a genuine
                # incoming network event, not a same-process fd-close
                # notification, so it isn't subject to that race.
                client_a.settimeout(2.0)
                self.assertEqual(client_a.sock.recv(4096), b"")

                # thread_a must actually exit. Sized with headroom over the
                # patched read timeout: the common case is a prompt close,
                # but the worst case is thread_a's own recv() falling back to
                # the (freshly-reset, still short) timeout above.
                thread_a.join(timeout=self._READ_TIMEOUT_SECONDS + 2.0)
                self.assertFalse(thread_a.is_alive())

                # ...and B must be reported CONNECTED without status ever
                # having dropped to WAITING in between (a stale session must
                # not be able to flap the UI while a reconnect takes over).
                wait_for_status(statuses, ServerState.CONNECTED)
                self.assertNotIn(ServerState.WAITING, [state for state, _ in statuses])
        finally:
            # Close the test's own client sockets first: that's a real
            # network-level close, so the peer's blocked recv() unblocks
            # promptly. Only close the server-side sockets afterwards,
            # once their handler threads have already joined -- closing
            # them earlier would race the same thread that's blocked in
            # recv() on them.
            client_a.close()
            if client_b is not None:
                client_b.close()
            stop_event.set()
            thread_a.join(timeout=1.0)
            if thread_b is not None:
                thread_b.join(timeout=1.0)
            connection_a.close()
            if connection_b is not None:
                connection_b.close()


class ReceiverReadTimeoutTests(unittest.TestCase):
    def test_silent_authenticated_client_is_declared_dead_after_the_read_timeout(self):
        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        with mock.patch.object(receiver, "SESSION_READ_TIMEOUT_SECONDS", 0.2):
            thread = threading.Thread(
                target=server._handle_client,
                args=(connection, address, make_config(), stop_event),
            )
            thread.start()
            try:
                client.send(protocol.hello_msg())
                self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
                wait_for_status(statuses, ServerState.CONNECTED)
                # Say nothing further. A dead/half-open peer must be detected
                # from the (now short) read timeout alone -- no TCP-level
                # close required.
                wait_for_status(statuses, ServerState.WAITING, timeout=2.0)
            finally:
                client.close()
                stop_event.set()
                thread.join(timeout=1.0)
                connection.close()
        self.assertFalse(thread.is_alive())


class ReceiverPingTests(unittest.TestCase):
    def test_ping_is_never_recorded_or_specially_acked(self):
        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            client.send(protocol.hello_msg())
            self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
            client.send(protocol.ping_msg())
            client.send(protocol.ping_msg())
            # A ping never bumps the processed sequence, so every ack the
            # client observes afterwards -- whether the periodic heartbeat or
            # one for a genuine event -- must still read seq 0.
            client.settimeout(1.0)
            self.assertEqual(client.recv(), protocol.ack_msg(0))
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=1.0)
            connection.close()


class HandleMessageInjectorTests(unittest.TestCase):
    def test_keydown_is_routed_to_the_injector(self):
        injector = FakeInjector()
        processed = handle_message(
            {"type": protocol.MSG_KEYDOWN, "data": {"key": "a"}}, injector=injector
        )
        self.assertTrue(processed)
        self.assertEqual(injector.calls, [("key", ("a", True))])

    def test_gesture_is_routed_to_the_injector_by_name(self):
        injector = FakeInjector()
        processed = handle_message(protocol.gesture_msg("swipe_up"), injector=injector)
        self.assertTrue(processed)
        self.assertEqual(injector.calls, [("gesture", ("swipe_up",))])

    def test_unknown_type_is_ignored(self):
        injector = FakeInjector()
        processed = handle_message({"type": "bogus", "data": {}}, injector=injector)
        self.assertFalse(processed)
        self.assertEqual(injector.calls, [])

    def test_scroll_passes_dx_and_mode_through_to_the_injector(self):
        injector = FakeInjector()
        processed = handle_message(
            {"type": protocol.MSG_SCROLL, "data": {"dy": 12.5, "dx": -3.25, "mode": "pixel"}},
            injector=injector,
        )
        self.assertTrue(processed)
        self.assertEqual(injector.calls, [("scroll", (12.5, -3.25, "pixel"))])

    def test_scroll_defaults_dx_and_mode_when_omitted(self):
        # Backward tolerance: an older sender (or a plain line-mode wheel
        # click) may omit dx/mode entirely.
        injector = FakeInjector()
        processed = handle_message(
            {"type": protocol.MSG_SCROLL, "data": {"dy": 1}}, injector=injector
        )
        self.assertTrue(processed)
        self.assertEqual(injector.calls, [("scroll", (1, 0, "line"))])


class ReceiverAckTests(unittest.TestCase):
    def test_a_burst_of_events_is_acked_once_promptly(self):
        # Input is acked as soon as it lands, batched by ACK_COALESCE_SECONDS:
        # a per-event ACK would roughly double packet count at ~100Hz mouse
        # rates, but the old fixed 400ms timer put up to 400ms of pure waiting
        # into the round trip the Mac measures and reports.
        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        with mock.patch.object(receiver, "ACK_IDLE_SECONDS", 1000.0), mock.patch.object(
            receiver, "ACK_COALESCE_SECONDS", 0.2
        ), mock.patch.object(input_injector, "inject_mouse_move"):
            thread = threading.Thread(
                target=server._handle_client,
                args=(connection, address, make_config(), stop_event),
            )
            thread.start()
            try:
                client.send(protocol.hello_msg())
                self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
                for _ in range(3):
                    client.send({"type": protocol.MSG_MOUSEMOVE, "data": {"dx": 1, "dy": 1}}
                    )
                # Well inside the parked idle heartbeat, so an ACK arriving at
                # all proves the burst itself woke the thread.
                client.settimeout(1.0)
                ack = client.recv()
                self.assertEqual(ack["type"], protocol.MSG_ACK)
                # seq 3 in the FIRST ACK is the coalescing: all three events
                # were covered by one reply rather than one ACK each. Asserting
                # on a second ACK not arriving would be a test of thread
                # scheduling, so it is deliberately not asserted here.
                self.assertEqual(ack["data"]["seq"], 3)
            finally:
                client.close()
                stop_event.set()
                thread.join(timeout=1.0)
                connection.close()

    def test_an_idle_link_still_gets_a_heartbeat_ack(self):
        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        with mock.patch.object(receiver, "ACK_IDLE_SECONDS", 0.05):
            thread = threading.Thread(
                target=server._handle_client,
                args=(connection, address, make_config(), stop_event),
            )
            thread.start()
            try:
                client.send(protocol.hello_msg())
                self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
                client.settimeout(1.0)
                ack = client.recv()
                self.assertEqual(ack["type"], protocol.MSG_ACK)
                self.assertEqual(ack["data"]["seq"], 0)
            finally:
                client.close()
                stop_event.set()
                thread.join(timeout=1.0)
                connection.close()


class ReceiverClipboardTests(unittest.TestCase):
    def test_focus_mac_replies_with_the_local_clipboard_text(self):
        statuses = []
        clipboard = FakeClipboard(text="hello from windows")
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            client.send(protocol.hello_msg())
            self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
            client.send(protocol.focus_msg("mac"))
            client.settimeout(1.0)
            self.assertEqual(client.recv(), protocol.clipboard_msg("hello from windows"))
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=1.0)
            connection.close()

    def test_focus_windows_is_a_reserved_noop(self):
        statuses = []
        clipboard = FakeClipboard(text="must not be sent")
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        with mock.patch.object(receiver, "ACK_IDLE_SECONDS", 1000.0):
            thread = threading.Thread(
                target=server._handle_client,
                args=(connection, address, make_config(), stop_event),
            )
            thread.start()
            try:
                client.send(protocol.hello_msg())
                self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
                client.send(protocol.focus_msg("windows"))
                client.settimeout(0.3)
                with self.assertRaises((socket.timeout, TimeoutError)):
                    client.recv()
            finally:
                client.close()
                stop_event.set()
                thread.join(timeout=1.0)
                connection.close()

    def test_focus_mac_with_empty_clipboard_sends_no_reply(self):
        statuses = []
        clipboard = FakeClipboard(text="")
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        with mock.patch.object(receiver, "ACK_IDLE_SECONDS", 1000.0):
            thread = threading.Thread(
                target=server._handle_client,
                args=(connection, address, make_config(), stop_event),
            )
            thread.start()
            try:
                client.send(protocol.hello_msg())
                self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
                client.send(protocol.focus_msg("mac"))
                client.settimeout(0.3)
                with self.assertRaises((socket.timeout, TimeoutError)):
                    client.recv()
            finally:
                client.close()
                stop_event.set()
                thread.join(timeout=1.0)
                connection.close()

    def test_focus_mac_with_oversized_clipboard_sends_no_reply(self):
        statuses = []
        clipboard = FakeClipboard(text="z" * (protocol.CLIPBOARD_MAX_BYTES + 1))
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        with mock.patch.object(receiver, "ACK_IDLE_SECONDS", 1000.0):
            thread = threading.Thread(
                target=server._handle_client,
                args=(connection, address, make_config(), stop_event),
            )
            thread.start()
            try:
                client.send(protocol.hello_msg())
                self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
                client.send(protocol.focus_msg("mac"))
                client.settimeout(0.3)
                with self.assertRaises((socket.timeout, TimeoutError)):
                    client.recv()
            finally:
                client.close()
                stop_event.set()
                thread.join(timeout=1.0)
                connection.close()

    def test_inbound_clipboard_sets_the_windows_clipboard(self):
        statuses = []
        clipboard = FakeClipboard()
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            client.send(protocol.hello_msg())
            self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
            client.send(protocol.clipboard_msg("copied on the Mac"))
            wait_for_calls(clipboard.set_calls, minimum=1)
            self.assertEqual(clipboard.set_calls, [("copied on the Mac", None)])
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=1.0)
            connection.close()

    def test_inbound_clipboard_ignores_oversized_payload(self):
        statuses = []
        clipboard = FakeClipboard()
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            client.send(protocol.hello_msg())
            self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
            oversized = "y" * (protocol.CLIPBOARD_MAX_BYTES + 1)
            client.send(protocol.clipboard_msg(oversized))
            # Follow up with a normal clipboard message and wait for that one
            # instead of sleeping blind: if the oversized one had been
            # applied, set_calls would already be non-empty by this point.
            client.send(protocol.clipboard_msg("ok"))
            wait_for_calls(clipboard.set_calls, minimum=1)
            self.assertEqual(clipboard.set_calls, [("ok", None)])
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=1.0)
            connection.close()

    def test_focus_mac_replies_with_text_and_image(self):
        statuses = []
        clipboard = FakeClipboard(text="shot.png", image=FAKE_PNG)
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            client.send(protocol.hello_msg())
            self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
            client.send(protocol.focus_msg("mac"))
            client.settimeout(1.0)
            self.assertEqual(client.recv(), protocol.clipboard_msg("shot.png", FAKE_PNG))
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=1.0)
            connection.close()

    def test_focus_mac_drops_an_oversized_image_but_sends_the_text(self):
        statuses = []
        big = protocol.PNG_SIGNATURE + b"\x00" * protocol.CLIPBOARD_IMAGE_MAX_BYTES
        clipboard = FakeClipboard(text="shot.png", image=big)
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            client.send(protocol.hello_msg())
            self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
            client.send(protocol.focus_msg("mac"))
            client.settimeout(1.0)
            self.assertEqual(client.recv(), protocol.clipboard_msg("shot.png"))
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=1.0)
            connection.close()

    def test_inbound_clipboard_sets_text_and_image_and_ignores_a_malformed_image(self):
        statuses = []
        clipboard = FakeClipboard()
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            client.send(protocol.hello_msg())
            self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
            client.send({"type": protocol.MSG_CLIPBOARD, "data": {"text": "bad", "image": "not base64!", "image_format": "png"}})
            client.send(protocol.clipboard_msg("shot.png", FAKE_PNG))
            wait_for_calls(clipboard.set_calls, minimum=2)
            self.assertEqual(clipboard.set_calls, [("bad", None), ("shot.png", FAKE_PNG)])
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=1.0)
            connection.close()

    def test_focus_and_clipboard_do_not_bump_the_processed_sequence(self):
        # Mirrors ReceiverPingTests.test_ping_is_never_recorded_or_specially_acked:
        # control messages must not be recorded, and must not trigger their
        # own immediate ack -- only the periodic ack timer's seq 0 shows up.
        statuses = []
        clipboard = FakeClipboard(text="")
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)), clipboard=clipboard)
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        try:
            client.send(protocol.hello_msg())
            self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
            client.send(protocol.focus_msg("windows"))
            client.send(protocol.clipboard_msg("from the mac"))
            client.settimeout(1.0)
            self.assertEqual(client.recv(), protocol.ack_msg(0))
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=1.0)
            connection.close()


class ReceiverCrossingTests(unittest.TestCase):
    """The way home, end to end on the wire: a focus that names the return
    edge arms it and places the pointer; pushing through it sends switch."""

    MONITORS = [Rect(0, 0, 2560, 1440), Rect(-1920, 200, 1920, 1080)]

    def _session(self, desktop, pressures=None):
        statuses = []
        server = ReceiverServer(
            lambda state, detail: statuses.append((state, detail)),
            clipboard=FakeClipboard(text=""),
            desktop=desktop,
            pressure_callback=None if pressures is None else (lambda *args: pressures.append(args)),
        )
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        client.send(protocol.hello_msg())
        self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
        return server, client, connection, stop_event, thread

    @staticmethod
    def _teardown(client, connection, stop_event, thread):
        client.close()
        stop_event.set()
        thread.join(timeout=1.0)
        connection.close()

    @staticmethod
    def _focus_windows(**extra):
        return {"type": protocol.MSG_FOCUS, "data": {"target": "windows", **extra}}

    def test_arrival_places_the_pointer_and_arms_the_return_edge(self):
        desktop = FakeDesktop(self.MONITORS, cursor=(500, 500))
        server, client, connection, stop_event, thread = self._session(desktop)
        try:
            client.send(self._focus_windows(edge="left", offset=0.5, return_edge="left", resistance_px=100))
            wait_for_calls(desktop.set_calls, minimum=1)
            self.assertEqual(desktop.set_calls, [(-1920, 720)])
            self.assertEqual(server.return_edge, "left")
        finally:
            self._teardown(client, connection, stop_event, thread)

    def test_shortcut_switch_arms_without_moving_the_pointer(self):
        desktop = FakeDesktop(self.MONITORS, cursor=(500, 500))
        server, client, connection, stop_event, thread = self._session(desktop)
        try:
            client.send(self._focus_windows(return_edge="top", resistance_px=120))
            client.send(protocol.ping_msg())
            client.settimeout(1.0)
            self.assertEqual(client.recv(), protocol.ack_msg(0))
            self.assertEqual(desktop.set_calls, [])
            self.assertEqual(server.return_edge, "top")
        finally:
            self._teardown(client, connection, stop_event, thread)

    def test_pushing_through_the_return_edge_sends_switch_to_the_mac(self):
        desktop = FakeDesktop(self.MONITORS, cursor=(-1920, 720))
        pressures = []
        with mock.patch.object(receiver, "ACK_IDLE_SECONDS", 1000.0), mock.patch.object(
            input_injector, "inject_mouse_move"
        ) as inject:
            server, client, connection, stop_event, thread = self._session(desktop, pressures)
            try:
                client.send(self._focus_windows(return_edge="left", resistance_px=100))
                client.send({"type": protocol.MSG_MOUSEMOVE, "data": {"dx": -60, "dy": 3}})
                client.send({"type": protocol.MSG_MOUSEMOVE, "data": {"dx": -60, "dy": 0}})
                client.settimeout(1.0)
                self.assertEqual(client.recv(), protocol.switch_msg("mac", "right", 723 / 1440))
                # Held at the edge first (clamped, lateral movement kept), then
                # crossed; neither move reached SendInput.
                self.assertEqual(desktop.set_calls, [(-1920, 723)])
                inject.assert_not_called()
                # The receiver sends the switch before it reports the breakthrough pressure, so
                # the second entry can land after recv() returns: 2 in 15 runs failed on the rig.
                wait_for_calls(pressures, minimum=2)
                self.assertEqual([edge for edge, _, _ in pressures], ["left", "left"])
                self.assertAlmostEqual(pressures[0][1], 0.6)
                self.assertEqual(pressures[1][1:], (1.0, True))
                # Disarmed after the crossing: the next move injects normally.
                client.send({"type": protocol.MSG_MOUSEMOVE, "data": {"dx": -60, "dy": 0}})
                wait_for_calls(inject.call_args_list, minimum=1)
                inject.assert_called_once_with(-60, 0)
            finally:
                self._teardown(client, connection, stop_event, thread)

    def test_moves_inject_normally_when_no_return_edge_is_armed(self):
        desktop = FakeDesktop(self.MONITORS, cursor=(-1920, 720))
        with mock.patch.object(input_injector, "inject_mouse_move") as inject:
            server, client, connection, stop_event, thread = self._session(desktop)
            try:
                client.send({"type": protocol.MSG_MOUSEMOVE, "data": {"dx": -60, "dy": 0}})
                wait_for_calls(inject.call_args_list, minimum=1)
                self.assertEqual(desktop.set_calls, [])
            finally:
                self._teardown(client, connection, stop_event, thread)


class ReceiverHandBackTests(unittest.TestCase):
    """The peer's input is here and the link that brought it ends. The peer
    fails open on its own side, but the focus saying so dies with the socket,
    so the receiver raises it: otherwise the owner keeps treating the peer as
    driving and its own edge and shortcut stay dead."""

    def _session(self, focuses):
        server = ReceiverServer(
            lambda state, detail: None,
            clipboard=FakeClipboard(text=""),
            desktop=FakeDesktop([Rect(0, 0, 1920, 1080)], cursor=(500, 500)),
            focus_callback=focuses.append,
        )
        client, connection, address = connected_socket_pair()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=server._handle_client,
            args=(connection, address, make_config(), stop_event),
        )
        thread.start()
        client.send(protocol.hello_msg())
        self.assertEqual(client.recv(), protocol.welcome_msg(platform="windows"))
        return server, client, connection, thread

    @staticmethod
    def _focus(target, **extra):
        return {"type": protocol.MSG_FOCUS, "data": {"target": target, **extra}}

    def test_a_peer_that_drops_while_driving_hands_input_back(self):
        focuses = []
        server, client, connection, thread = self._session(focuses)
        try:
            client.send(self._focus("windows", return_edge="left", resistance_px=100))
            wait_for_calls(focuses, minimum=1)
            self.assertEqual(server.return_edge, "left")
            client.close()
            thread.join(timeout=2.0)
            self.assertEqual(focuses, ["windows", "mac"])
            self.assertIsNone(server.return_edge)
        finally:
            connection.close()

    def test_send_home_while_driving_sends_the_peer_its_input(self):
        # The escape that does not depend on the return edge: 23-09-2026, the
        # PC's mouse stayed on the Mac after a push through the edge never fired.
        focuses = []
        server, client, connection, thread = self._session(focuses)
        try:
            client.send(self._focus("windows", return_edge="left", resistance_px=100))
            wait_for_calls(focuses, minimum=1)
            self.assertTrue(server.send_home())
            client.settimeout(1.0)
            self.assertEqual(client.recv(), protocol.switch_msg("mac"))
            self.assertIsNone(server.return_edge)
        finally:
            client.close()
            thread.join(timeout=2.0)
            connection.close()

    def test_send_home_with_input_already_home_does_nothing(self):
        focuses = []
        server, client, connection, thread = self._session(focuses)
        try:
            self.assertFalse(server.send_home())
        finally:
            client.close()
            thread.join(timeout=2.0)
            connection.close()

    def test_a_peer_that_drops_with_input_at_home_says_nothing_more(self):
        focuses = []
        server, client, connection, thread = self._session(focuses)
        try:
            client.send(self._focus("windows"))
            client.send(self._focus("mac"))
            wait_for_calls(focuses, minimum=2)
            client.close()
            thread.join(timeout=2.0)
            self.assertEqual(focuses, ["windows", "mac"])
        finally:
            connection.close()

    def test_stopping_the_listener_while_driving_hands_input_back(self):
        focuses = []
        server, client, connection, thread = self._session(focuses)
        try:
            client.send(self._focus("windows", return_edge="left", resistance_px=100))
            wait_for_calls(focuses, minimum=1)
            server.stop()
            self.assertEqual(focuses, ["windows", "mac"])
            self.assertIsNone(server.return_edge)
            client.close()
            thread.join(timeout=2.0)
            # The session's own end finds nothing left to hand back.
            self.assertEqual(focuses, ["windows", "mac"])
        finally:
            connection.close()

    def test_a_peer_that_reconnects_while_driving_starts_with_input_at_home(self):
        focuses = []
        server, client, connection, thread = self._session(focuses)
        try:
            client.send(self._focus("windows"))
            wait_for_calls(focuses, minimum=1)
            # A second session authenticates before the first has noticed
            # anything: the preempt closes the first, and either way the
            # peer's input is at home the moment it is back.
            second_client, second_connection, second_address = connected_socket_pair()
            second_thread = threading.Thread(
                target=server._handle_client,
                args=(second_connection, second_address, make_config(), threading.Event()),
            )
            second_thread.start()
            second_client.send(protocol.hello_msg())
            self.assertEqual(second_client.recv(), protocol.welcome_msg(platform="windows"))
            wait_for_calls(focuses, minimum=2)
            self.assertEqual(focuses, ["windows", "mac"])
            second_client.close()
            second_thread.join(timeout=2.0)
            self.assertEqual(focuses, ["windows", "mac"])
            second_connection.close()
            client.close()
            thread.join(timeout=2.0)
        finally:
            connection.close()


class ReceiverBindTests(unittest.TestCase):
    def test_a_held_port_is_waited_out_rather_than_ending_the_listener(self):
        # WinNAT's dynamic reservations move on every reboot and have landed on
        # Beamer's port, which used to kill the server thread for the whole run.
        holder = socket.socket()
        # The receiver listens on 0.0.0.0, and SO_REUSEADDR only collides with
        # a holder on the same address, so 127.0.0.1 here would bind happily.
        holder.bind(("0.0.0.0", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        self.addCleanup(holder.close)

        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        self.addCleanup(server.stop)
        with mock.patch.object(receiver, "BIND_RETRY_SECONDS", 0.05):
            server.start(make_config(port=port))
            _, detail = wait_for_status(statuses, ServerState.ERROR, timeout=2.0)
            self.assertIn(f"port {port}", detail)
            self.assertIn("Connection page", detail)
            holder.close()
            deadline = time.monotonic() + 3.0
            waiting = (ServerState.WAITING, f"Waiting on port {port}")
            while waiting not in statuses and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIn(waiting, statuses)

    def test_a_reuseaddr_zombie_still_blocks_the_new_bind(self):
        # A held port is normally a third-party program (the test above) or a
        # WinNAT reservation, but it can also be a zombie copy of Beamer
        # itself, whose listener was opened by this same _bind() and so also
        # carries SO_REUSEADDR. If Windows' SO_REUSEADDR let a second
        # SO_REUSEADDR socket steal a listening one, this is the scenario
        # where it would happen — the "held port" detection would never fire
        # and the two zombies would silently split inbound connections.
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("0.0.0.0", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        self.addCleanup(holder.close)

        statuses = []
        server = ReceiverServer(lambda state, detail: statuses.append((state, detail)))
        self.addCleanup(server.stop)
        with mock.patch.object(receiver, "BIND_RETRY_SECONDS", 0.05):
            server.start(make_config(port=port))
            _, detail = wait_for_status(statuses, ServerState.ERROR, timeout=2.0)
            self.assertIn(f"port {port}", detail)


if __name__ == "__main__":
    unittest.main()
