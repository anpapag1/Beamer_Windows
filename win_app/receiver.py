"""Threaded TCP receiver and ACK watchdog for the Windows tray app."""

import logging
import math
import socket
import sys
import threading
import time
from enum import Enum
from typing import Callable, Optional

import return_edge as crossing
import protocol


LOGGER = logging.getLogger(__name__)
# `config` throughout is whichever settings object the app on this side keeps.
# Only `port` and `auth_token` are ever read from it, and the two apps' classes
# are unrelated types, so it is not annotated or imported here -- importing one
# app's config module would stop this file being the other app's as well.
# The longest an idle link goes without an ACK, so the Mac's watchdog keeps
# seeing a heartbeat when nothing is being typed.
ACK_IDLE_SECONDS = 0.4
# How long an ACK waits after input arrives, batching a burst into one reply.
# A per-event ACK at ~100Hz mouse rates would roughly double the packet count;
# 15ms caps it near 66/s while keeping the round trip the Mac reports honest,
# which a 400ms timer did not -- every reading carried up to 400ms of waiting
# that was never network latency.
ACK_COALESCE_SECONDS = 0.015
HELLO_TIMEOUT_SECONDS = 5.0
SESSION_READ_TIMEOUT_SECONDS = 2.5
INJECTION_ERROR_STATUS_INTERVAL_SECONDS = 5.0
# Windows hands the port back only when whatever holds it lets go — WinNAT's
# dynamic reservations move on every reboot and can land on ours — so a bind
# that fails is waited out rather than ending the listener.
BIND_RETRY_SECONDS = 5.0
# Connections still inside the handshake. Each is bounded to HELLO_TIMEOUT_SECONDS as a whole,
# so a stranger holding these slots loses them within seconds, while the real peer's handshake
# takes milliseconds and always finds one free.
MAX_PENDING_CONNECTIONS = 4


class ServerState(Enum):
    STOPPED = "Stopped"
    WAITING = "Waiting"
    CONNECTED = "Connected"
    ERROR = "Error"


class ProcessedSequence:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._latest = 0
        self._fallback = 0

    def record(self, message: dict) -> int:
        data = message.get("data", {})
        raw_sequence = message.get("seq")
        if raw_sequence is None and isinstance(data, dict):
            raw_sequence = data.get("seq")
        with self._lock:
            if isinstance(raw_sequence, int) and not isinstance(raw_sequence, bool) and raw_sequence >= 0:
                self._latest = max(self._latest, raw_sequence)
                self._fallback = max(self._fallback, self._latest)
            else:
                self._fallback = max(self._fallback, self._latest) + 1
                self._latest = self._fallback
            return self._latest

    def latest(self) -> int:
        with self._lock:
            return self._latest


def handle_message(message: dict, injector=None) -> bool:
    """Inject one input event. `injector` defaults to the real input_injector
    module, imported lazily here (not at module load) so receiver.py stays
    importable — and its non-injection logic testable — on a machine without
    ctypes.windll. The Mac copy of this file is handed its own injector at
    construction and never reaches that import. Tests can pass a fake
    injector directly."""
    if injector is None:
        import input_injector as injector
    if not isinstance(message, dict):
        raise protocol.ProtocolError("message body must be a JSON object")
    message_type = message.get("type")
    data = message.get("data", {})
    if not isinstance(data, dict):
        raise protocol.ProtocolError("message data must be a JSON object")
    if message_type == protocol.MSG_KEYDOWN:
        injector.inject_key(data["key"], down=True)
    elif message_type == protocol.MSG_KEYUP:
        injector.inject_key(data["key"], down=False)
    elif message_type == protocol.MSG_MOUSEMOVE:
        injector.inject_mouse_move(int(data["dx"]), int(data["dy"]))
    elif message_type == protocol.MSG_MOUSEDOWN:
        injector.inject_mouse_button(data["button"], down=True)
    elif message_type == protocol.MSG_MOUSEUP:
        injector.inject_mouse_button(data["button"], down=False)
    elif message_type == protocol.MSG_SCROLL:
        injector.inject_scroll(data["dy"], data.get("dx", 0), data.get("mode", "line"))
    elif message_type == protocol.MSG_GESTURE:
        injector.inject_gesture(data["name"])
    else:
        LOGGER.warning("Unknown message type ignored: %r", message_type)
        return False
    return True


class ReceiverServer:
    def __init__(
        self,
        status_callback: Callable[[ServerState, str], None],
        clipboard=None,
        unlock=None,
        desktop=None,
        pressure_callback: Optional[Callable[[str, float, bool], None]] = None,
        injector=None,
        focus_callback: Optional[Callable[[str], None]] = None,
        peer_callback: Optional[Callable[[str, Optional[str], Optional[int], Optional[str]], None]] = None,
        arrangement_callback: Optional[Callable[[str, int], None]] = None,
        self_name: str = "PC",
        peer_name: str = "Mac",
        self_target: str = "windows",
        peer_target: str = "mac",
    ) -> None:
        # One module serves both machines: this file is byte-identical in
        # win_app and mac_app, which test_receiver_parity enforces. Everything
        # platform-shaped is handed in -- the injector, clipboard, desktop
        # geometry and unlock modules, the two names that appear in status
        # text, and the two wire target words -- so nothing below knows which
        # side it is running on. `focus_callback(target)` fires on every focus
        # message, which is how the app that owns this receiver knows input
        # has arrived or gone home -- and once more with the peer's own target
        # when the link that brought input here ends before the peer has
        # taken it back, because the peer fails open on its side and the
        # message saying so never reaches a dead socket.
        self._injector = injector
        self._focus_callback = focus_callback
        self._peer_driving = False
        # `peer_callback(host, return_edge, resistance_px, platform)` fires once per
        # authenticated connection, with the peer's address, the way home
        # its hello carried, and the OS the peer declares itself to be --
        # None when an older peer did not say. It is how the machine on this
        # side learns which border to push out across without anyone
        # configuring it twice -- the way home from there is the way out from
        # here -- and which modifier mapping the peer expects.
        self._peer_callback = peer_callback
        # `arrangement_callback(mac_edge, set_at)` fires when the peer says
        # where the two machines are in relation to each other. Either end may
        # change it, so this is how the change arrives at the end that did not
        # make it.
        self._arrangement_callback = arrangement_callback
        self._self_name = self_name
        self._peer_name = peer_name
        self._self_target = self_target
        self._peer_target = peer_target
        self._status_callback = status_callback
        # `desktop` defaults to the real desktop_win module, imported lazily for
        # the same reason as `clipboard` below. `pressure_callback(edge,
        # pressure, crossed)` is called on the session thread as the pointer
        # is pushed against the return edge; the GUI marshals it to the glow.
        self._desktop = desktop
        self._pressure_callback = pressure_callback
        # The way home. Armed by every focus{target:"windows"} the Mac sends,
        # which carries the return edge and resistance, and None until then.
        self._return_edge: Optional[crossing.ReturnEdge] = None
        # `unlock` defaults to the real unlock_win module, imported lazily for
        # the same reason as `clipboard` below.
        self._unlock = unlock
        # Set while a lock-screen unlock is in flight. Input that arrives in
        # that window is dropped rather than queued: an unlock takes several
        # seconds, and replaying seconds of stale mouse moves and keystrokes
        # onto the desktop the moment it appears is worse than losing them.
        self._unlocking = threading.Event()
        # `clipboard` defaults to the real clipboard_win module, imported
        # lazily (not at module load) so receiver.py stays importable -- and
        # its non-clipboard logic testable -- on a machine without
        # ctypes.windll, e.g. this Mac. Tests can pass a fake directly, the
        # same way handle_message's `injector` argument works.
        self._clipboard = clipboard
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event: Optional[threading.Event] = None
        self._listener: Optional[socket.socket] = None
        self._client: Optional[socket.socket] = None
        # The live session per connection, so a message can be sent to the
        # client from outside its own thread -- which is what an arrangement
        # changed in the window needs.
        self._sessions: dict = {}
        self._connections: set = set()
        self._pending = 0
        self._session_generation = 0
        self._requested_running = False

    @property
    def listening(self) -> bool:
        with self._lock:
            return self._requested_running and self._thread is not None and self._thread.is_alive()

    @property
    def return_edge(self) -> Optional[str]:
        """The Windows edge the Mac last named as the way home, or None."""
        model = self._return_edge
        return model.edge if model is not None else None

    @property
    def return_resistance(self) -> Optional[int]:
        """How many pixels of push the Mac last asked for at the return edge, or None."""
        model = self._return_edge
        return model.resistance_px if model is not None else None

    def start(self, config) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._server_thread,
                args=(config, stop_event),
                name="Beamer-server",
                daemon=True,
            )
            self._stop_event = stop_event
            self._thread = thread
            self._requested_running = True
        self._set_status(ServerState.WAITING, f"Starting on port {config.port}")
        try:
            thread.start()
        except Exception:
            with self._lock:
                if self._thread is thread:
                    self._thread = None
                    self._stop_event = None
                    self._requested_running = False
            raise

    def stop(self) -> None:
        with self._lock:
            self._requested_running = False
            stop_event = self._stop_event
            listener = self._listener
            connections = set(self._connections)
            thread = self._thread
        if stop_event is not None:
            stop_event.set()
        for connection in connections:
            self._close_socket(connection)
        self._close_socket(listener)
        # start() publishes the thread under the lock and starts it outside, so a
        # stop() landing in that window would join a thread that never started,
        # which raises rather than returning.
        if thread is not None and thread is not threading.current_thread() and thread.ident is not None:
            thread.join(timeout=2.0)
        if thread is not None and thread.is_alive():
            LOGGER.error("Server thread did not stop within two seconds")
            self._set_status(ServerState.ERROR, "Listener did not stop; see log")
            return
        with self._lock:
            if self._thread is thread:
                self._thread = None
                self._stop_event = None
                self._listener = None
                self._client = None
        self._hand_back("Listening stopped")
        self._set_status(ServerState.STOPPED, "Listening stopped")

    def _server_thread(self, config, stop_event: threading.Event) -> None:
        failed = False
        try:
            self._serve(config, stop_event)
        except Exception as exc:
            if not stop_event.is_set():
                failed = True
                LOGGER.exception("Server thread failed")
                self._set_status(ServerState.ERROR, f"Listener failed: {exc}")
        finally:
            with self._lock:
                listener = self._listener
                connections = set(self._connections)
                self._listener = None
                self._client = None
                if self._thread is threading.current_thread():
                    self._thread = None
                    self._stop_event = None
                if failed:
                    self._requested_running = False
            for connection in connections:
                self._close_socket(connection)
            self._close_socket(listener)
            if stop_event.is_set():
                self._set_status(ServerState.STOPPED, "Listening stopped")

    def _bind(self, config, stop_event: threading.Event):
        """Bind the listening socket, waiting for the port if something holds it."""
        reported = ""
        while not stop_event.is_set():
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # On the Mac this is what lets the port be taken back straight
            # after a restart, while the last session's connections sit in
            # TIME_WAIT. On Windows the same option means something else: a
            # second bind on a port another listener holds succeeds, and the
            # two split the Mac's connections between them, so the held-port
            # wait below never fired for a zombie Beamer (rig, 22-09-2026).
            # Windows does not need it for TIME_WAIT, so it does without.
            if sys.platform != "win32":
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind(("0.0.0.0", config.port))
            except OSError as exc:
                self._close_socket(listener)
                # Said the way a user can act on it: the log carries the error, the
                # status carries the one thing they can change.
                detail = f"Another program is using port {config.port} — change the port on the Connection page"
                # Only on a change: a retry every few seconds otherwise repeats
                # the same line and the same status for as long as the port is held.
                if detail != reported:
                    LOGGER.error("Cannot listen on port %s: %s", config.port, exc)
                    reported = detail
                    self._set_status(ServerState.ERROR, detail)
                stop_event.wait(BIND_RETRY_SECONDS)
                continue
            return listener
        return None

    def _serve(self, config, stop_event: threading.Event) -> None:
        listener = self._bind(config, stop_event)
        if listener is None:
            return
        # A stale, not-yet-torn-down session must never block a reconnect: a
        # backlog of 2 lets a fresh Mac connection queue up while the previous
        # session's thread is still winding down, instead of the OS refusing
        # it outright.
        listener.listen(2)
        listener.settimeout(0.5)
        with self._lock:
            self._listener = listener
        LOGGER.info("Listening on 0.0.0.0:%s", config.port)
        self._set_status(ServerState.WAITING, f"Waiting on port {config.port}")
        while not stop_event.is_set():
            try:
                connection, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if stop_event.is_set():
                    break
                raise
            # Hand the connection to its own thread immediately and go back
            # to accept(): a slow or stuck peer must never stall the listener,
            # which is what used to make a stale session block a reconnect.
            # Bounded, because accept() happens before any proof of the token.
            # Only handshakes count: an authenticated peer never blocks the
            # next one, and a stranger's slot frees itself within seconds.
            with self._lock:
                crowded = self._pending >= MAX_PENDING_CONNECTIONS
                if not crowded:
                    self._pending += 1
            if crowded:
                LOGGER.warning("Refusing %s:%s: %d handshakes already in progress", address[0], address[1], MAX_PENDING_CONNECTIONS)
                self._close_socket(connection)
                continue
            thread = threading.Thread(
                target=self._session_thread,
                args=(connection, address, config, stop_event),
                name="Beamer-session",
                daemon=True,
            )
            thread.start()

    def _session_thread(
        self,
        connection: socket.socket,
        address,
        config,
        server_stop: threading.Event,
    ) -> None:
        with self._lock:
            self._connections.add(connection)
        try:
            self._handle_client(connection, address, config, server_stop)
        finally:
            with self._lock:
                self._connections.discard(connection)
            self._close_socket(connection)

    def _handle_client(
        self,
        connection: socket.socket,
        address,
        config,
        server_stop: threading.Event,
    ) -> None:
        peer = f"{address[0]}:{address[1]}"
        LOGGER.info("Connection from %s", peer)
        try:
            handshake = self._handshake(connection, peer, config, server_stop)
        finally:
            with self._lock:
                self._pending -= 1
        if handshake is None:
            return
        session, version, hello = handshake

        if version != protocol.PROTOCOL_VERSION:
            LOGGER.warning(
                "Rejecting %s: unsupported protocol version %r (expected %s)",
                peer,
                version,
                protocol.PROTOCOL_VERSION,
            )
            self._send_message(connection, session, protocol.welcome_msg(error="version_mismatch"))
            self._note_version_mismatch(f"{self._peer_name} app is an older Beamer version — update both apps")
            return

        # The Mac now pings at least once a second while idle, so a read
        # timeout here means the peer is gone, not merely quiet.
        connection.settimeout(SESSION_READ_TIMEOUT_SECONDS)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sequence = ProcessedSequence()
        # The wire target word for this side is the OS name in both apps, so it
        # is what gets declared -- not `sys.platform`, which would call this
        # receiver Windows even where it is configured to act as the Mac.
        if not self._send_message(connection, session, protocol.welcome_msg(platform=self._self_target)):
            return

        with self._lock:
            previous_client = self._client
            self._client = connection
            self._sessions[connection] = session
            self._session_generation += 1
            my_generation = self._session_generation
        if previous_client is not None and previous_client is not connection:
            # Preempt: a reconnecting Mac instantly replaces a stale session
            # instead of queueing behind it. Closing it here unblocks that
            # thread's blocked recv so it can exit.
            LOGGER.info("Superseding the previous session for %s", peer)
            self._close_socket(previous_client)

        peer_platform = hello.get("platform") if isinstance(hello, dict) else None
        LOGGER.info("Authenticated %s (protocol v%s, platform %s)", peer, version, peer_platform or "unspecified")
        # A peer that has just connected has its input at home, whatever the
        # session it replaced was in the middle of.
        self._hand_back(f"{self._peer_name} reconnected")
        self._notify_peer(address[0], hello)
        self._set_status(ServerState.CONNECTED, f"Connected to {address[0]}")

        client_stop = threading.Event()
        ack_due = threading.Event()
        ack_thread = threading.Thread(
            target=self._ack_thread,
            args=(connection, session, sequence, client_stop, server_stop, ack_due),
            name="Beamer-ack",
            daemon=True,
        )
        ack_thread.start()

        last_injection_status_at = 0.0
        try:
            while not server_stop.is_set() and not client_stop.is_set():
                try:
                    message = protocol.recv_msg(connection, session)
                except socket.timeout:
                    if self._is_current_session(my_generation):
                        LOGGER.warning("%s went quiet; treating the connection as dead", peer)
                    break
                except protocol.ConnectionClosed:
                    if self._is_current_session(my_generation):
                        LOGGER.info("%s disconnected", peer)
                    break
                except protocol.ProtocolError as exc:
                    if self._is_current_session(my_generation):
                        LOGGER.warning("Protocol error from %s: %s", peer, exc)
                    break
                except OSError as exc:
                    if (
                        not server_stop.is_set()
                        and not client_stop.is_set()
                        and self._is_current_session(my_generation)
                    ):
                        LOGGER.warning("Receive failed for %s: %s", peer, exc)
                    break
                message_type = message.get("type") if isinstance(message, dict) else None
                if message_type == protocol.MSG_PING:
                    # Liveness only; never recorded or acked as an input event.
                    continue
                if message_type == protocol.MSG_FOCUS:
                    # Never recorded or acked as an input event, like ping.
                    self._handle_focus(message, connection, session, peer, address[0])
                    continue
                if message_type == protocol.MSG_CLIPBOARD:
                    # Never recorded or acked as an input event, like ping.
                    self._handle_inbound_clipboard(message, peer)
                    continue
                if message_type == protocol.MSG_ARRANGEMENT:
                    # Never recorded or acked as an input event, like ping.
                    self._handle_arrangement(message)
                    continue
                if self._unlocking.is_set():
                    # Dropped, not queued: see _begin_unlock. Still recorded so
                    # the ACK sequence stays continuous and the Mac's watchdog
                    # does not read the unlock as a dead link.
                    sequence.record(message)
                    continue
                if message_type == protocol.MSG_MOUSEMOVE and self._return_trip(message, connection, session):
                    # Held at the edge or crossed: not injected, but still an
                    # input event for the ACK sequence.
                    sequence.record(message)
                    continue
                try:
                    processed = handle_message(message, self._injector)
                except Exception:
                    LOGGER.exception("Input event from %s could not be injected", peer)
                    now = time.monotonic()
                    if now - last_injection_status_at >= INJECTION_ERROR_STATUS_INTERVAL_SECONDS:
                        last_injection_status_at = now
                        self._set_status(ServerState.CONNECTED, f"Input error from {address[0]}; see log")
                    continue
                if not processed:
                    continue
                sequence.record(message)
                ack_due.set()
        finally:
            client_stop.set()
            ack_thread.join(timeout=1.0)
            if ack_thread.is_alive():
                LOGGER.error("ACK thread did not stop within one second")
                self._set_status(ServerState.ERROR, "ACK worker did not stop; see log")
            with self._lock:
                self._sessions.pop(connection, None)
                is_current = self._session_generation == my_generation
                if is_current:
                    self._client = None
            if is_current:
                self._hand_back(f"{self._peer_name} went away")
            # A preempted (superseded) session must exit silently: only the
            # current-generation session may flip status to WAITING.
            if is_current and not server_stop.is_set():
                self._set_status(ServerState.WAITING, f"Waiting on port {config.port}")

    def _is_current_session(self, generation: int) -> bool:
        with self._lock:
            return self._session_generation == generation

    def _handshake(self, connection: socket.socket, peer: str, config, server_stop: threading.Event):
        """Read the Mac's preamble, answer with ours, then open its hello.
        Returns (session, declared version) or None once the failure has been
        logged. The preamble is read before ours is sent so an older Mac, which
        opens with a cleartext frame instead, gets a cleartext version_mismatch
        it can display rather than bytes it reads as a bogus length."""
        connection.settimeout(HELLO_TIMEOUT_SECONDS)
        # One deadline for the whole handshake, not a timeout per read: a peer
        # trickling a byte at a time would otherwise hold its slot for ever.
        deadline = time.monotonic() + HELLO_TIMEOUT_SECONDS
        session = protocol.SecureSession(config.auth_token)
        try:
            try:
                protocol.recv_preamble(connection, session, deadline=deadline)
            except protocol.VersionMismatch as exc:
                if exc.peer_version is None:
                    LOGGER.warning("%s opened with the pre-v4 cleartext protocol", peer)
                    connection.sendall(protocol.legacy_frame(protocol.welcome_msg(error="version_mismatch")))
                    self._note_version_mismatch(f"{self._peer_name} app is an older Beamer version — update both apps")
                else:
                    LOGGER.warning("%s speaks wire version %r, expected %s", peer, exc.peer_version, protocol.PROTOCOL_VERSION)
                    connection.sendall(session.preamble())
                    self._note_version_mismatch(
                        f"{self._peer_name} app is Beamer protocol v{exc.peer_version}, this {self._self_name} is v{protocol.PROTOCOL_VERSION} — update both apps"
                    )
                return None
            connection.sendall(session.preamble())
            first = protocol.recv_msg(connection, session, limit=protocol.HELLO_MAX_BYTES, deadline=deadline)
        except socket.timeout:
            LOGGER.warning("Authentication timed out for %s", peer)
            return None
        except protocol.ConnectionClosed:
            LOGGER.info("%s disconnected before authentication", peer)
            return None
        except protocol.AuthenticationError:
            # The one signal that the Mac does not hold the shared token. Nothing is sent back:
            # a reply would tell a guesser it had reached a Beamer.
            LOGGER.warning("Authentication failed for %s: frame failed authentication", peer)
            return None
        except protocol.ProtocolError as exc:
            LOGGER.warning("Protocol error during authentication from %s: %s", peer, exc)
            return None
        except OSError as exc:
            if not server_stop.is_set():
                LOGGER.warning("Authentication receive failed for %s: %s", peer, exc)
            return None
        if first.get("type") != protocol.MSG_HELLO:
            LOGGER.warning("%s authenticated but did not say hello first", peer)
            return None
        data = first.get("data")
        return session, self._hello_version(first), data if isinstance(data, dict) else {}

    def _note_version_mismatch(self, detail: str) -> None:
        with self._lock:
            has_active_client = self._client is not None
        if not has_active_client:
            self._set_status(ServerState.ERROR, detail)

    def _ack_thread(
        self,
        connection: socket.socket,
        session: protocol.SecureSession,
        sequence: ProcessedSequence,
        client_stop: threading.Event,
        server_stop: threading.Event,
        ack_due: threading.Event,
    ) -> None:
        try:
            while not server_stop.is_set():
                woken = ack_due.wait(ACK_IDLE_SECONDS)
                if client_stop.is_set():
                    return
                if woken:
                    ack_due.clear()
                    # Coalesce on client_stop, not sleep, so a disconnect during
                    # the batching window still exits promptly.
                    if client_stop.wait(ACK_COALESCE_SECONDS):
                        return
                ack = protocol.ack_msg(sequence.latest(), locked=self._unlocking.is_set())
                if not self._send_message(connection, session, ack):
                    client_stop.set()
                    self._close_socket(connection)
                    return
        except Exception as exc:
            LOGGER.exception("ACK thread failed")
            self._set_status(ServerState.ERROR, f"ACK worker failed: {exc}")
            client_stop.set()
            self._close_socket(connection)

    def _clipboard_module(self):
        if self._clipboard is not None:
            return self._clipboard
        import clipboard_win
        return clipboard_win

    def _unlock_module(self):
        if self._unlock is not None:
            return self._unlock
        import unlock_win
        return unlock_win

    def _desktop_module(self):
        if self._desktop is not None:
            return self._desktop
        import desktop_win
        return desktop_win

    def _return_trip(self, message: dict, connection: socket.socket, session: protocol.SecureSession) -> bool:
        """The return path. Feeds every mouse move to the pressure model while
        a return edge is armed; True means the move was consumed — the pointer
        was held at the edge, or it broke through and the Mac has been asked
        to take input back — and must not be injected."""
        model = self._return_edge
        if model is None or not model.armed:
            return False
        data = message.get("data")
        if not isinstance(data, dict):
            return False
        try:
            desktop = self._desktop_module()
            outcome = model.feed(desktop.monitors(), desktop.cursor_position(), float(data["dx"]), float(data["dy"]))
            if outcome.action == crossing.HOLD:
                desktop.set_cursor_position(*outcome.position)
            elif outcome.action == crossing.CROSS:
                LOGGER.info("Pointer pushed through the %s edge; returning input to the %s", model.edge, self._peer_name)
                self._send_message(connection, session, protocol.switch_msg(self._peer_target, outcome.edge, outcome.offset))
        except Exception:
            # Logged once, not at 100Hz: the return edge is dropped until the
            # Mac's next switch re-arms it, and input keeps flowing normally.
            LOGGER.exception("Return edge failed; crossing back is off until the next switch")
            self._return_edge = None
            return False
        if outcome.action == crossing.PASS:
            return False
        self._notify_pressure(model.edge, outcome.pressure, outcome.action == crossing.CROSS)
        return True

    def send_arrangement(self, mac_edge: str, set_at: int) -> bool:
        """Tell the peer where the machines are, over the connection it opened
        to this one. Used when the change was made at this end: the outward
        link may be down, or may not exist on this machine at all, and this
        one is up by definition whenever there is anyone to tell."""
        with self._lock:
            connection = self._client
            session = self._session_for(connection)
        if connection is None or session is None:
            return False
        return self._send_message(connection, session, protocol.arrangement_msg(mac_edge, set_at))

    def send_home(self) -> bool:
        """Send the peer's input back to it from this end, as its own return
        edge would. The escape that does not depend on that edge: the owner
        calls it when someone here asks to switch while the peer is driving,
        which was refused outright until the 23-09-2026 afternoon a push
        through the edge never fired and the PC's mouse stayed on the Mac.
        The send runs on its own thread, because the callers are a hook and
        an event tap that must never block on a socket."""
        with self._lock:
            connection = self._client
            session = self._session_for(connection)
        if not self._peer_driving or connection is None or session is None:
            return False
        self._return_edge = None
        LOGGER.info("Switch asked for here; sending input home to the %s", self._peer_name)
        threading.Thread(
            target=self._send_message,
            args=(connection, session, protocol.switch_msg(self._peer_target)),
            name="Beamer-send-home",
            daemon=True,
        ).start()
        return True

    def _session_for(self, connection):
        return self._sessions.get(connection) if connection is not None else None

    def _handle_arrangement(self, message: dict) -> None:
        read = protocol.read_arrangement(message.get("data"))
        if read is None or self._arrangement_callback is None:
            return
        try:
            self._arrangement_callback(*read)
        except Exception:
            LOGGER.exception("Arrangement callback failed")

    def _notify_peer(self, host: str, hello: dict) -> None:
        if self._peer_callback is None:
            return
        edge = hello.get("return_edge")
        if edge not in crossing.EDGES:
            edge = None
        resistance = hello.get("resistance_px")
        if isinstance(resistance, bool) or not isinstance(resistance, (int, float)):
            resistance = None
        platform = hello.get("platform")
        if platform is None:
            # A peer that declared nothing is read in this receiver's own terms.
            # The two apps name the same wire targets as each other's OS, so
            # this side's configured role is the only thing known here -- and it
            # is not a guess, it is what this side was set up to be.
            platform = self._self_target
        try:
            self._peer_callback(host, edge, None if resistance is None else int(resistance), platform)
        except Exception:
            LOGGER.exception("Peer callback failed")

    def _notify_focus(self, target) -> None:
        if self._focus_callback is None or not isinstance(target, str):
            return
        if target == self._self_target:
            self._peer_driving = True
        elif target == self._peer_target:
            self._peer_driving = False
        try:
            self._focus_callback(target)
        except Exception:
            LOGGER.exception("Focus callback failed")

    def _hand_back(self, why: str) -> None:
        """The peer's input was on this machine and the link that carried it
        is over. The peer has already failed open on its own side; the focus
        that would have said so died with the socket, so it is raised here.
        Otherwise the owner of this receiver keeps treating the peer as
        driving, and its own edge and shortcut stay dead until the peer next
        crosses in and back."""
        if not self._peer_driving:
            return
        self._return_edge = None
        LOGGER.info("%s while its input was here; input returned to this %s", why, self._self_name)
        self._release_peer_keys()
        self._notify_focus(self._peer_target)

    def _release_peer_keys(self) -> None:
        """Let go of whatever the peer was holding here. A modifier or button
        injected for the peer and never released -- a chord in flight when
        input went home or the link died -- would otherwise stay down on this
        machine, turning every later local keystroke into a shortcut."""
        injector = self._injector
        if injector is None:
            try:
                import input_injector as injector
            except Exception:
                LOGGER.exception("Injector unavailable; keys the peer held may still be down")
                return
        release = getattr(injector, "release_all", None)
        if release is None:
            return
        try:
            release()
        except Exception:
            LOGGER.exception("Could not release the keys the %s was holding", self._peer_name)

    def _notify_pressure(self, edge: str, pressure: float, crossed: bool) -> None:
        if self._pressure_callback is None:
            return
        try:
            self._pressure_callback(edge, pressure, crossed)
        except Exception:
            LOGGER.exception("Pressure callback failed")

    def _arm_return(self, data: dict) -> None:
        """Every switch to Windows says which edge leads home and how hard to
        push; an older Mac that says neither gets no return edge, so nothing
        it does not expect can fire."""
        edge = data.get("return_edge")
        if edge not in crossing.EDGES:
            self._return_edge = None
            return
        resistance = data.get("resistance_px", crossing.DEFAULT_RESISTANCE_PX)
        # json.loads accepts Infinity and NaN, and int() of either raises, which
        # nothing above this catches: a bad number gets the default instead.
        if isinstance(resistance, bool) or not isinstance(resistance, (int, float)) or not math.isfinite(resistance):
            resistance = crossing.DEFAULT_RESISTANCE_PX
        self._return_edge = crossing.ReturnEdge(edge, int(resistance))

    def _place_pointer(self, data: dict) -> None:
        edge = data.get("edge")
        offset = data.get("offset")
        if edge not in crossing.EDGES or isinstance(offset, bool) or not isinstance(offset, (int, float)):
            return
        try:
            desktop = self._desktop_module()
            desktop.set_cursor_position(*crossing.arrival_position(desktop.monitors(), edge, offset))
        except Exception:
            LOGGER.exception("Could not place the pointer at the %s edge on arrival", edge)

    def _begin_unlock(self, peer: str, host: str) -> None:
        """Take the console off the lock screen, if it is on one, so the input
        about to arrive has somewhere to land. Beamer cannot type on the secure
        desktop at all -- see unlock_win -- so without this, switching to a
        locked PC silently injects into nothing.

        The lock test is a cheap in-process snapshot, so the common case (an
        unlocked PC) stays inline and costs nothing. Only a real unlock goes to
        a thread, because it takes seconds and this runs on the message loop
        that has to keep draining pings."""
        try:
            unlock = self._unlock_module()
        except Exception:
            LOGGER.exception("Unlock support unavailable")
            return
        if unlock.is_locked() is not True:
            return
        if self._unlocking.is_set():
            return
        self._unlocking.set()
        LOGGER.info("%s switched to a locked PC; asking the provider to unlock", peer)
        self._set_status(ServerState.CONNECTED, "Unlocking Windows…")
        with self._lock:
            generation = self._session_generation
        threading.Thread(
            target=self._unlock_worker,
            args=(unlock, peer, host, generation),
            name="Beamer-unlock",
            daemon=True,
        ).start()

    def _unlock_worker(self, unlock, peer: str, host: str, generation: int) -> None:
        try:
            unlocked = unlock.ensure_unlocked()
        except Exception:
            LOGGER.exception("Unlock failed for %s", peer)
            unlocked = False
        finally:
            self._unlocking.clear()
        # An unlock takes seconds, so the Mac may have gone in the meantime and
        # the session's own exit already have set WAITING. Only the session
        # that asked for this unlock may report its outcome.
        if not self._is_current_session(generation):
            return
        if unlocked:
            self._set_status(ServerState.CONNECTED, f"Connected to {host}")
        else:
            self._set_status(
                ServerState.CONNECTED, "Windows is locked — unlock it at the PC"
            )

    def _handle_focus(
        self,
        message: dict,
        connection: socket.socket,
        session: protocol.SecureSession,
        peer: str,
        host: str,
    ) -> None:
        """`focus{target:"mac"}` means the Mac just switched input back to
        itself: reply with this Windows clipboard's text so the Mac's
        pasteboard picks up whatever was last copied here.
        `target:"windows"` means input is coming here: learn the way home
        from it, land the pointer where a crossing says, and clear the lock
        screen out of its way."""
        data = message.get("data")
        target = data.get("target") if isinstance(data, dict) else None
        if target == self._peer_target:
            # Released before the owner hears input is home: the Mac's tap
            # comes back on at that notice, and a modifier still down would
            # chord with the first local keystroke.
            self._return_edge = None
            self._release_peer_keys()
        self._notify_focus(target)
        if target == self._self_target:
            self._arm_return(data)
            self._place_pointer(data)
            self._begin_unlock(peer, host)
            return
        if target != self._peer_target:
            return
        clipboard = self._clipboard_module()
        try:
            text, image = clipboard.get_contents()
        except Exception:
            LOGGER.exception("Failed to read the local clipboard for %s", peer)
            return
        if text and len(text.encode("utf-8")) > protocol.CLIPBOARD_MAX_BYTES:
            LOGGER.warning("Local clipboard text too large; skipping the text for %s", peer)
            text = None
        if image is not None and len(image) > protocol.CLIPBOARD_IMAGE_MAX_BYTES:
            LOGGER.warning(
                "Local clipboard image is %d bytes, over the %d cap; skipping the image for %s",
                len(image),
                protocol.CLIPBOARD_IMAGE_MAX_BYTES,
                peer,
            )
            image = None
        if not text and image is None:
            return
        self._send_message(connection, session, protocol.clipboard_msg(text or None, image))

    def _handle_inbound_clipboard(self, message: dict, peer: str) -> None:
        data = message.get("data")
        text = data.get("text") if isinstance(data, dict) else None
        if not isinstance(text, str) or not text:
            text = None
        elif len(text.encode("utf-8")) > protocol.CLIPBOARD_MAX_BYTES:
            LOGGER.warning("Ignoring oversized inbound clipboard text from %s", peer)
            text = None
        image = protocol.clipboard_image(data)
        if text is None and image is None:
            return
        clipboard = self._clipboard_module()
        try:
            if not clipboard.set_contents(text, image):
                LOGGER.warning("Failed to set the local clipboard for %s", peer)
        except Exception:
            LOGGER.exception("Failed to set the local clipboard for %s", peer)

    @staticmethod
    def _hello_version(message: dict):
        data = message.get("data", {})
        if not isinstance(data, dict):
            return None
        return data.get("version")

    @staticmethod
    def _send_message(
        connection: socket.socket,
        session: protocol.SecureSession,
        message: dict,
    ) -> bool:
        """The session's own lock serialises the seal and the write together,
        so frames reach the wire in counter order from every thread."""
        try:
            protocol.send_msg(connection, session, message)
            return True
        except (OSError, protocol.ProtocolError) as exc:
            LOGGER.warning("Send failed: %s", exc)
            return False

    def _set_status(self, state: ServerState, detail: str) -> None:
        try:
            self._status_callback(state, detail)
        except Exception:
            LOGGER.exception("Status callback failed")

    @staticmethod
    def _close_socket(sock: Optional[socket.socket]) -> None:
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
