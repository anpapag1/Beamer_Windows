"""The Windows-to-Mac direction, driven over a real loopback socket against
the same receiver.py the Mac runs, so the two halves are proved against each
other rather than against a mock of each other."""

import socket
import threading
import time
import unittest

import capture_win
import protocol
import receiver
import sender
from app_config import Config
from fakes import FakeClipboard, FakeDesktop, FakeInjector, wait_for_calls
from return_edge import Rect

MONITORS = [Rect(0, 0, 1920, 1080)]


def make_config(**overrides):
    values = dict(
        host="127.0.0.1",
        port=0,
        auth_token="shared-token",
        mac_host="127.0.0.1",
        mac_return_edge="left",
        mac_resistance_px=40,
        crossing_resistance_px=40,
    )
    values.update(overrides)
    return Config(**values)


class EdgeTests(unittest.TestCase):
    """The outward crossing, with no link in the way: the model, the gate and
    the pin, which is everything the hook thread does per mouse move."""

    def setUp(self):
        self.desktop = FakeDesktop(MONITORS, cursor=(0, 500))
        self.link = MacSenderWithLink(desktop=self.desktop)

    def tearDown(self):
        self.link.close()

    def push(self, times, dx=-20):
        """The hand still moving left with the cursor already stopped at the
        left edge: the position never changes, which is exactly why the
        movement has to come from raw input rather than from the hook."""
        for _ in range(times):
            self.link.sender.on_motion(dx, 0)

    def test_a_push_against_the_edge_crosses(self):
        self.push(4)
        self.assertTrue(self.link.sender.redirecting, "a sustained push against the left edge never crossed")

    def test_the_push_lights_the_edge_it_is_pressing(self):
        # The app once built its sender with no pressure callback, so the PC's own push out to
        # the Mac crossed in the dark while the same edge lit for the Mac's push home.
        seen = []
        self.link.sender._pressure_callback = lambda edge, pressure, crossed: seen.append((edge, crossed))
        self.push(4)
        self.assertTrue(seen, "a push against the edge reported no pressure")
        self.assertTrue(all(edge == "left" for edge, _ in seen))
        self.assertEqual(seen[-1][1], True)

    def test_this_pcs_own_mouse_pushing_out_while_the_mac_drives_takes_the_pointer_across(self):
        # 27-09-2026: the Mac's trackpad crossed to the PC, and the PC's own mouse could not push
        # back out. The Mac's injected moves carry INJECTED_MARK and never reach on_motion, so a
        # push here is the hand's: the Mac gets its input back and this mouse follows it across.
        sent_home = []
        self.link.sender.send_peer_home = lambda: sent_home.append(True) or True
        self.link.sender.set_receiving(True)
        self.push(4)
        self.assertEqual(sent_home, [True])
        self.assertTrue(self.link.sender.redirecting)

    def test_a_push_while_the_mac_drives_and_cannot_be_sent_home_stays_here(self):
        self.link.sender.send_peer_home = lambda: False
        self.link.sender.set_receiving(True)
        self.push(10)
        self.assertFalse(self.link.sender.redirecting)

    def test_the_shortcut_while_the_mac_is_driving_sends_its_input_home(self):
        sent_home = []
        self.link.sender.send_peer_home = lambda: sent_home.append(True) or True
        self.link.sender.set_receiving(True)
        self.assertTrue(self.link.sender.set_redirecting(True))
        self.assertEqual(sent_home, [True])
        self.assertFalse(self.link.sender.redirecting)

    def test_a_push_away_from_the_edge_never_crosses(self):
        self.push(10, dx=20)
        self.assertFalse(self.link.sender.redirecting)

    def test_a_pointer_off_the_edge_never_crosses(self):
        self.desktop.cursor = (900, 500)
        self.push(10)
        self.assertFalse(self.link.sender.redirecting)

    def test_the_edge_can_be_turned_off(self):
        self.link.sender.update_config(make_config(crossing_methods=["shortcut"]))
        self.push(10)
        self.assertFalse(self.link.sender.redirecting)
        self.assertTrue(self.link.sender.shortcut_armed)

    def test_the_shortcut_can_be_turned_off_on_its_own(self):
        self.link.sender.update_config(make_config(crossing_methods=["edge"]))
        self.assertFalse(self.link.sender.shortcut_armed)
        self.push(4)
        self.assertTrue(self.link.sender.redirecting)


class CornerTests(unittest.TestCase):
    """The corner is for a machine whose whole edge is busy: it wants a
    diagonal push in an 8-pixel box, and nothing else."""

    def setUp(self):
        self.desktop = FakeDesktop(MONITORS, cursor=(0, 0))
        self.link = MacSenderWithLink(desktop=self.desktop)
        self.link.sender.update_config(
            make_config(crossing_methods=["corner"], crossing_corner="top_left")
        )

    def tearDown(self):
        self.link.close()

    def test_a_diagonal_push_in_the_corner_crosses(self):
        for _ in range(4):
            self.link.sender.on_motion(-20, -20)
        self.assertTrue(self.link.sender.redirecting)

    def test_a_straight_push_along_the_edge_does_not(self):
        for _ in range(10):
            self.link.sender.on_motion(-20, 0)
        self.assertFalse(self.link.sender.redirecting)

    def test_the_same_diagonal_away_from_the_corner_does_not(self):
        self.desktop.cursor = (900, 500)
        for _ in range(10):
            self.link.sender.on_motion(-20, -20)
        self.assertFalse(self.link.sender.redirecting)


class SelfConnectionTests(unittest.TestCase):
    """The one way this PC could take its own daily link down: learning its
    own address as the Mac's, connecting to its own receiver with the shared
    token, and having the preempt rule close the real Mac's session."""

    def test_loopback_and_this_pcs_own_addresses_are_refused(self):
        self.assertTrue(sender.is_this_machine("127.0.0.1"))
        self.assertTrue(sender.is_this_machine("0.0.0.0"))
        self.assertTrue(sender.is_this_machine(""))
        self.assertTrue(sender.is_this_machine("192.168.1.3", ["192.168.1.3"]))

    def test_the_macs_address_is_not(self):
        self.assertFalse(sender.is_this_machine("192.168.1.5", ["192.168.1.3"], address_towards=lambda host: "192.168.1.3"))

    def test_this_pcs_own_real_address_is_not_missed_when_enumeration_fails(self):
        # local_addresses=[] is what pairing._local_ipv4_addresses() returns
        # when the hostname does not resolve; the route probe then answers,
        # and for this PC's own address it answers with that address.
        self.assertTrue(sender.is_this_machine("192.168.1.3", [], address_towards=lambda host: host))
        self.assertFalse(sender.is_this_machine("192.168.1.5", [], address_towards=lambda host: "192.168.1.3"))

    def test_a_route_probe_that_fails_does_not_stop_the_link(self):
        def refuse(host):
            raise OSError("network is unreachable")

        self.assertFalse(sender.is_this_machine("192.168.1.5", [], address_towards=refuse))

    def test_a_sender_pointed_at_this_pc_never_opens_a_link(self):
        attempts = []

        def refuse(address, timeout):
            attempts.append(address)
            raise AssertionError("the sender tried to connect to this PC")

        link = sender.MacSender(socket_factory=refuse, desktop=FakeDesktop(MONITORS))
        link.update_config(make_config(mac_host="127.0.0.1", port=51820))
        self.assertIsNone(link._ready_config())
        self.assertEqual(attempts, [])


class LinkTests(unittest.TestCase):
    def setUp(self):
        self.injector = FakeInjector()
        self.clipboard = FakeClipboard()
        self.mac_desktop = FakeDesktop(MONITORS, cursor=(900, 500))
        self.statuses = []
        self.arrangements = []
        self.server = receiver.ReceiverServer(
            status_callback=lambda state, detail: self.statuses.append((state, detail)),
            arrangement_callback=lambda edge, set_at: self.arrangements.append((edge, set_at)),
            clipboard=self.clipboard,
            unlock=NoUnlock(),
            desktop=self.mac_desktop,
            injector=self.injector,
            self_name="Mac",
            peer_name="PC",
            self_target="mac",
            peer_target="windows",
        )
        self.port = free_port()
        self.server.start(Config(host="127.0.0.1", port=self.port, auth_token="shared-token"))
        self.desktop = FakeDesktop(MONITORS, cursor=(0, 500))
        # The loopback address is this PC's own, which the real guard refuses
        # to connect to; here it is the Mac at the other end of the test.
        self.sender = sender.MacSender(
            desktop=self.desktop, clipboard=FakeClipboard("copied"), is_local=lambda host: False
        )
        self.sender.start(make_config(port=self.port))
        self.assertTrue(wait_for(lambda: self.sender.connected), f"never connected: {self.sender.status}")

    def tearDown(self):
        self.sender.stop()
        self.server.stop()

    def test_keys_reach_the_mac_injector(self):
        self.sender.set_redirecting(True, arrival_edge="right", offset=0.5)
        self.sender.on_key("cmd", True)
        self.sender.on_key("c", True)
        self.sender.on_key("c", False)
        self.sender.on_key("cmd", False)
        wait_for_calls(self.injector.calls, 4)
        self.assertEqual(
            self.injector.calls,
            [
                ("key", ("cmd", True)),
                ("key", ("c", True)),
                ("key", ("c", False)),
                ("key", ("cmd", False)),
            ],
        )

    def test_the_switch_places_the_mac_pointer_and_arms_its_way_home(self):
        self.sender.set_redirecting(True, arrival_edge="right", offset=0.25)
        self.assertTrue(wait_for(lambda: self.server.return_edge == "right"))
        self.assertEqual(self.mac_desktop.cursor[0], MONITORS[0].right)

    def test_nothing_is_sent_while_input_is_this_pcs(self):
        self.sender.on_key("a", True)
        time.sleep(0.2)
        self.assertEqual(self.injector.calls, [])

    def test_the_mac_pushing_home_takes_input_back(self):
        self.sender.set_redirecting(True, arrival_edge="right", offset=0.5)
        self.assertTrue(wait_for(lambda: self.server.return_edge == "right"))
        # The Mac's own pointer, pushed off its right edge: the receiver
        # answers with a switch, which must stop this PC sending.
        self.mac_desktop.cursor = (MONITORS[0].right, 500)
        for _ in range(20):
            self.sender.on_motion(40, 0)
            self.mac_desktop.cursor = (MONITORS[0].right, 500)
            if not self.sender.redirecting:
                break
        self.assertTrue(wait_for(lambda: not self.sender.redirecting), "the Mac's push home was ignored")

    def test_the_arrangement_travels_to_the_mac(self):
        self.sender.send_arrangement("right", 1758100000)
        wait_for_calls(self.arrangements, 1)
        self.assertEqual(self.arrangements[0], ("right", 1758100000))

    def test_the_arrangement_travels_back_from_the_mac(self):
        heard = []
        self.sender._arrangement_callback = lambda edge, set_at: heard.append((edge, set_at))
        self.assertTrue(self.server.send_arrangement("top", 1758100001))
        wait_for_calls(heard, 1)
        self.assertEqual(heard[0], ("top", 1758100001))

    def test_a_malformed_arrangement_does_not_take_the_link_down(self):
        self.sender._send_raw({"type": protocol.MSG_ARRANGEMENT, "data": {"mac_edge": "sideways"}})
        time.sleep(0.2)
        self.assertEqual(self.arrangements, [])
        self.assertTrue(self.sender.connected)

    def test_the_clipboard_travels_with_the_switch(self):
        self.sender.set_redirecting(True, arrival_edge="right", offset=0.5)
        wait_for_calls(self.clipboard.set_calls, 1)
        self.assertEqual(self.clipboard.set_calls[0][0], "copied")


class ConnectionFailedTests(unittest.TestCase):
    """A deliberate stop drops the socket before the reader thread's blocked
    recv() notices, so the OSError it then raises names a socket nobody owns
    any more -- Windows' WinError 10038 on the off switch, reproduced here
    without a real stop()."""

    def setUp(self):
        self.statuses = []
        self.redirected = []
        self.sender = sender.MacSender(
            status_callback=lambda connected, detail: self.statuses.append(detail),
            redirect_callback=self.redirected.append,
        )

    def test_an_error_on_an_already_dropped_socket_is_not_a_failure(self):
        old_sock, peer = socket.socketpair()
        self.addCleanup(old_sock.close)
        self.addCleanup(peer.close)
        self.sender._sock = old_sock
        self.sender.redirecting = True
        self.sender._sock = None  # what stop()/_drop_connection() does first
        self.sender._connection_failed("Receiving from the Mac failed: boom", expected_socket=old_sock)
        self.assertEqual(self.statuses, [])
        self.assertEqual(self.redirected, [])
        self.assertTrue(self.sender.redirecting, "a stale error forced input back to this PC")

    def test_an_error_on_the_live_socket_is_still_reported(self):
        sock, peer = socket.socketpair()
        self.addCleanup(sock.close)
        self.addCleanup(peer.close)
        self.sender._sock = sock
        self.sender.redirecting = True
        self.sender._connection_failed("Receiving from the Mac failed: boom", expected_socket=sock)
        self.assertEqual(self.statuses, ["Receiving from the Mac failed: boom"])
        self.assertFalse(self.sender.redirecting)



class WindowsPeerProtocolTests(unittest.TestCase):
    def test_switch_from_windows_peer_triggers_switch_back(self):
        # Verify sender accepts switch_msg target from another Windows receiver
        s = sender.MacSender(redirect_callback=lambda val: None)
        s.redirecting = True
        # Windows receiver sends switch_msg with peer_target ("mac" or "peer" or "windows")
        s._handle_switch({"target": "mac"})
        self.assertFalse(s.redirecting)

        s.redirecting = True
        s._handle_switch({"target": "peer"})
        self.assertFalse(s.redirecting)

        s.redirecting = True
        s._handle_switch({"target": "windows"})
        self.assertFalse(s.redirecting)

        s.redirecting = True
        s._handle_switch({"target": "unknown"})
        self.assertTrue(s.redirecting)

    def test_focus_target_when_peer_is_windows(self):
        s = sender.MacSender(desktop=FakeDesktop(MONITORS), peer_target="windows")
        s._sock = object()
        s._last_ack_at = time.monotonic()
        s.set_redirecting(True)
        msgs = []
        while not s._outbound.empty():
            msgs.append(s._outbound.get_nowait())
        focus_msgs = [m for m in msgs if m.get("type") == protocol.MSG_FOCUS]
        self.assertTrue(focus_msgs)
        self.assertEqual(focus_msgs[0]["data"]["target"], "windows")

        s.set_redirecting(False)
        msgs = []
        while not s._outbound.empty():
            msgs.append(s._outbound.get_nowait())
        focus_msgs = [m for m in msgs if m.get("type") == protocol.MSG_FOCUS]
        self.assertTrue(focus_msgs)
        self.assertEqual(focus_msgs[0]["data"]["target"], "mac")

    def test_set_redirecting_target_parameter(self):
        s = sender.MacSender(desktop=FakeDesktop(MONITORS))
        s._sock = object()
        s._last_ack_at = time.monotonic()
        s.set_redirecting(True, target="windows")
        msgs = []
        while not s._outbound.empty():
            msgs.append(s._outbound.get_nowait())
        focus_msgs = [m for m in msgs if m.get("type") == protocol.MSG_FOCUS]
        self.assertEqual(focus_msgs[0]["data"]["target"], "windows")

        s.set_redirecting(False, target="custom_return")
        msgs = []
        while not s._outbound.empty():
            msgs.append(s._outbound.get_nowait())
        focus_msgs = [m for m in msgs if m.get("type") == protocol.MSG_FOCUS]
        self.assertEqual(focus_msgs[0]["data"]["target"], "custom_return")

    def test_windows_peer_wire_name_modifier_mapping(self):
        s = sender.MacSender(desktop=FakeDesktop(MONITORS), peer_target="windows")
        self.assertTrue(s._peer_is_windows)
        # Ctrl captured as "cmd"/"cmd_r" becomes wire "ctrl"/"ctrl_r"
        self.assertEqual(s._wire_name("cmd"), "ctrl")
        self.assertEqual(s._wire_name("cmd_r"), "ctrl_r")
        # Win captured as "ctrl"/"ctrl_r" becomes wire "cmd"/"cmd_r"
        self.assertEqual(s._wire_name("ctrl"), "cmd")
        self.assertEqual(s._wire_name("ctrl_r"), "cmd_r")
        # Other modifiers and keys remain unchanged
        self.assertEqual(s._wire_name("alt"), "alt")
        self.assertEqual(s._wire_name("alt_r"), "alt_r")
        self.assertEqual(s._wire_name("shift"), "shift")
        self.assertEqual(s._wire_name("shift_r"), "shift_r")
        self.assertEqual(s._wire_name("c"), "c")

    def test_peer_is_windows_flag_override(self):
        s = sender.MacSender(desktop=FakeDesktop(MONITORS), peer_target="mac")
        self.assertFalse(s._peer_is_windows)
        self.assertEqual(s._wire_name("cmd"), "cmd")
        s._peer_is_windows = True
        self.assertTrue(s._peer_is_windows)
        self.assertEqual(s._wire_name("cmd"), "ctrl")

    def test_windows_peer_on_key_sends_identity_modifiers(self):
        s = sender.MacSender(desktop=FakeDesktop(MONITORS), peer_target="windows")
        s._sock = object()
        s._last_ack_at = time.monotonic()
        s.set_redirecting(True)
        while not s._outbound.empty():
            s._outbound.get_nowait()

        # Physical Ctrl press on Windows is captured as "cmd"
        s.on_key("cmd", True, vk=0xA2)
        s.on_key("c", True, vk=0x43)
        s.on_key("c", False, vk=0x43)
        s.on_key("cmd", False, vk=0xA2)

        # Physical Win press on Windows is captured as "ctrl"
        s.on_key("ctrl", True, vk=0x5B)
        s.on_key("ctrl", False, vk=0x5B)

        msgs = []
        while not s._outbound.empty():
            msgs.append(s._outbound.get_nowait())

        key_msgs = [(m["type"], m["data"]["key"]) for m in msgs if m.get("type") in (protocol.MSG_KEYDOWN, protocol.MSG_KEYUP)]
        self.assertEqual(
            key_msgs,
            [
                (protocol.MSG_KEYDOWN, "ctrl"),
                (protocol.MSG_KEYDOWN, "c"),
                (protocol.MSG_KEYUP, "c"),
                (protocol.MSG_KEYUP, "ctrl"),
                (protocol.MSG_KEYDOWN, "cmd"),
                (protocol.MSG_KEYUP, "cmd"),
            ],
        )

    def test_windows_peer_custom_key_map_override(self):
        s = sender.MacSender(desktop=FakeDesktop(MONITORS), peer_target="windows")
        cfg = make_config()
        cfg.key_map = {"cmd": "alt", "f1": "escape"}
        s.update_config(cfg)
        self.assertEqual(s._wire_name("cmd"), "alt")
        self.assertEqual(s._wire_name("f1"), "escape")
        # Non-overridden modifiers still use 1:1 Windows mapping
        self.assertEqual(s._wire_name("ctrl"), "cmd")



class NoUnlock:
    def is_locked(self):
        return None


class MacSenderWithLink:
    """A sender with no socket at all, for the edge tests: `connected` is
    forced true so the gate opens, and nothing is ever sent."""

    def __init__(self, desktop):
        self.sender = sender.MacSender(desktop=desktop, clipboard=FakeClipboard(), is_local=lambda host: False)
        self.sender.update_config(make_config())
        self.sender._sock = object()
        self.sender._connected_at = time.monotonic()
        self.sender._last_ack_at = time.monotonic()

    def close(self):
        self.sender._sock = None


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


if __name__ == "__main__":
    unittest.main()
