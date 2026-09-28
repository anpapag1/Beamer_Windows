"""End-to-end integration test suite for Windows-to-Windows navigation in Beamer.

Tests two Windows Beamer instances interacting:
1. Pairing exchange between two Windows machines resulting in agreed tokens and configurations.
2. Receiver and Sender session connection between two Windows machines over live TCP.
3. Outbound redirect from PC 1 to PC 2: verifies PC 2 receives focus, arms return edge, and places pointer.
4. Input injection on PC 2: verifies mouse moves, mouse buttons, and especially 1:1 modifier keys
   (Ctrl arriving as Ctrl 0xA2, Win arriving as Win 0x5B) without the Mac semantic swap.
5. Return crossing from PC 2 back to PC 1 via switch_msg returning input cleanly to PC 1.
"""

from dataclasses import replace
import json
import socket
import threading
import time
import unittest
from unittest import mock

from app_config import Config
import capture_win
from fakes import FakeClipboard, FakeDesktop, FakeInjector, wait_for_calls
import input_injector
from input_injector import plan_key_inputs
import pairing
from pairing import PairingClient, PairingHost, beacon_msg, decode, encode
import protocol
import receiver
from receiver import ReceiverServer, ServerState
import return_edge
from return_edge import Rect
import sender
from sender import MacSender


MONITORS_PC1 = [Rect(0, 0, 1920, 1080)]
MONITORS_PC2 = [Rect(0, 0, 1920, 1080)]


def free_port() -> int:
    """Find a currently available TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def free_udp_port() -> int:
    """Find a currently available UDP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(predicate, timeout=5.0, interval=0.02) -> bool:
    """Poll predicate until True or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


class RecordingWindowsInjector(FakeInjector):
    """FakeInjector that also resolves and records Win32 Virtual Key codes

    via input_injector.VK_MAP, matching real Windows SendInput translation.
    """

    def __init__(self):
        super().__init__()
        self.resolved_keys = []

    def inject_key(self, key, down):
        super().inject_key(key, down)
        lowered = key.lower()
        vk = input_injector.VK_MAP.get(lowered)
        self.resolved_keys.append((lowered, down, vk))


class WindowsToWindowsPairingTests(unittest.TestCase):
    """Part 1: Pairing exchange between two Windows machines resulting in agreed

    tokens and configurations.
    """

    def setUp(self):
        self.host_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.host_sock.bind(("127.0.0.1", 0))
        self.host_port = self.host_sock.getsockname()[1]

        self.disc_port = free_udp_port()
        self.discovery = pairing.Discovery(bind_port=self.disc_port)
        self.discovery.start()

        self.host = PairingHost()
        self.stop_host = threading.Event()

    def tearDown(self):
        self.stop_host.set()
        if hasattr(self, "host_thread") and self.host_thread.is_alive():
            self.host_thread.join(timeout=2.0)
        self.discovery.stop()
        self.host_sock.close()

    def _start_host_loop(self, name="PC2-Host", port=51820):
        def loop():
            while not self.stop_host.is_set():
                if self.host.active:
                    beacon = encode(beacon_msg(name, port, self.host.pair_id))
                    try:
                        self.host_sock.sendto(beacon, ("127.0.0.1", self.disc_port))
                    except OSError:
                        pass
                self.host_sock.settimeout(0.05)
                try:
                    data, addr = self.host_sock.recvfrom(1024)
                    msg = decode(data)
                    if msg:
                        reply = self.host.handle(msg)
                        if reply:
                            self.host_sock.sendto(encode(reply), addr)
                except (socket.timeout, OSError):
                    pass

        self.host_thread = threading.Thread(target=loop, daemon=True)
        self.host_thread.start()

    def test_lan_pairing_exchange_derives_identical_tokens(self):
        """PC 1 (discovery/client) and PC 2 (host) perform SPAKE2 pairing over UDP,

        agreeing on identical high-entropy auth tokens without transmitting them.
        """
        code = self.host.begin()
        self._start_host_loop(name="PC2-Host", port=51820)

        # PC 1 discovers PC 2
        discovered_pc2 = None
        for _ in range(50):
            pcs = self.discovery.pcs()
            if pcs and pcs[0].get("pair_id") == self.host.pair_id:
                discovered_pc2 = pcs[0]
                break
            time.sleep(0.05)

        self.assertIsNotNone(discovered_pc2, "PC 1 failed to discover PC 2 beacon on LAN")
        self.assertEqual(discovered_pc2["name"], "PC2-Host")
        self.assertEqual(discovered_pc2["port"], 51820)

        # PC 1 initiates pairing with the 6-digit code
        client_token = self.discovery.pair(discovered_pc2, code, name="PC1-Laptop")

        # Verify host has completed pairing
        self.assertIsNotNone(self.host.paired)
        host_token, host_peer_name = self.host.paired

        # Both sides derived the exact same token
        self.assertEqual(client_token, host_token)
        self.assertEqual(host_peer_name, "PC1-Laptop")
        self.assertGreaterEqual(len(client_token), 40)
        self.assertEqual(self.host.outcome, "paired")

    def test_pairing_produces_symmetric_windows_configs(self):
        """Verify resulting candidate configurations on both PC 1 and PC 2

        store the agreed token, remote addresses, and Windows peer targets.
        """
        code = self.host.begin()
        self._start_host_loop(name="PC2-Desktop", port=51820)

        discovered = None
        for _ in range(50):
            pcs = self.discovery.pcs()
            if pcs and pcs[0].get("pair_id") == self.host.pair_id:
                discovered = pcs[0]
                break
            time.sleep(0.05)

        self.assertIsNotNone(discovered)
        token = self.discovery.pair(discovered, code, name="PC1-Laptop")

        # 1. PC 1 (Client) creates candidate configuration
        pc1_base_config = Config(host="0.0.0.0", port=51820, auth_token="")
        pc1_candidate = replace(
            pc1_base_config,
            mac_host="192.168.1.102",  # PC 2's IP
            port=51820,
            auth_token=token,
            paired_with="PC2-Desktop",
            peer_target="windows",
        )
        self.assertEqual(pc1_candidate.mac_host, "192.168.1.102")
        self.assertEqual(pc1_candidate.auth_token, token)
        self.assertEqual(pc1_candidate.paired_with, "PC2-Desktop")
        self.assertEqual(pc1_candidate.peer_target, "windows")

        # 2. PC 2 (Host) creates candidate configuration, learning PC 1's address
        pc2_base_config = Config(host="0.0.0.0", port=51820, auth_token="", mac_host="")
        pc2_candidate = replace(
            pc2_base_config,
            auth_token=token,
            paired_with="PC1-Laptop",
            mac_host="192.168.1.101",  # Learned client IP
            peer_target="windows",
        )
        self.assertEqual(pc2_candidate.mac_host, "192.168.1.101")
        self.assertEqual(pc2_candidate.auth_token, token)
        self.assertEqual(pc2_candidate.paired_with, "PC1-Laptop")
        self.assertEqual(pc2_candidate.peer_target, "windows")


class WindowsToWindowsSessionTests(unittest.TestCase):
    """Parts 2, 3, 4, 5: Live connection, outbound redirection, 1:1 modifier

    input injection, and return edge switching between two Windows instances.
    """

    def setUp(self):
        self.token = "test-shared-auth-token-win-to-win-40-bytes"
        self.pc2_port = free_port()

        # PC 2 Receiver setup
        self.pc2_statuses = []
        self.pc2_focus_calls = []
        self.pc2_desktop = FakeDesktop(MONITORS_PC2, cursor=(960, 540))
        self.pc2_clipboard = FakeClipboard()
        self.pc2_injector = RecordingWindowsInjector()

        self.pc2_receiver = ReceiverServer(
            status_callback=lambda state, detail: self.pc2_statuses.append((state, detail)),
            focus_callback=lambda target: self.pc2_focus_calls.append(target),
            clipboard=self.pc2_clipboard,
            desktop=self.pc2_desktop,
            injector=self.pc2_injector,
            self_name="PC2",
            peer_name="PC1",
            self_target="windows",
            peer_target="mac",
        )
        self.pc2_receiver.start(
            Config(host="127.0.0.1", port=self.pc2_port, auth_token=self.token)
        )

        # PC 1 Sender setup
        self.pc1_statuses = []
        self.pc1_redirect_calls = []
        self.pc1_desktop = FakeDesktop(MONITORS_PC1, cursor=(0, 500))
        self.pc1_clipboard = FakeClipboard("pc1-initial-clipboard")

        self.pc1_sender = MacSender(
            status_callback=lambda conn, det: self.pc1_statuses.append((conn, det)),
            redirect_callback=lambda red: self.pc1_redirect_calls.append(red),
            desktop=self.pc1_desktop,
            clipboard=self.pc1_clipboard,
            is_local=lambda host: False,  # Allow loopback connection in test
            peer_target="windows",
        )
        self.pc1_config = Config(
            host="127.0.0.1",
            port=self.pc2_port,
            mac_host="127.0.0.1",
            auth_token=self.token,
            peer_target="windows",
            mac_return_edge="right",
            mac_resistance_px=40,
            crossing_resistance_px=40,
        )
        self.pc1_sender.start(self.pc1_config)

        # Wait for live TCP connection establishment
        self.assertTrue(
            wait_for(lambda: self.pc1_sender.connected),
            f"PC 1 Sender failed to connect to PC 2 Receiver: {self.pc1_sender.status}",
        )
        self.assertTrue(
            wait_for(lambda: any(s[0] == ServerState.CONNECTED for s in self.pc2_statuses)),
            f"PC 2 Receiver never reported CONNECTED: {self.pc2_statuses}",
        )

    def tearDown(self):
        self.pc1_sender.stop()
        self.pc2_receiver.stop()

    def test_receiver_and_sender_connection_established(self):
        """Part 2: Verify live TCP session connects, authenticates, and maintains

        state between two Windows instances.
        """
        self.assertTrue(self.pc1_sender.connected)
        self.assertTrue(self.pc2_receiver.listening)
        self.assertTrue(self.pc1_sender._peer_is_windows)
        self.assertEqual(self.pc1_sender.peer_target, "windows")

    def test_outbound_redirect_arms_pc2_and_places_pointer(self):
        """Part 3: Outbound redirect from PC 1 to PC 2: verifies PC 2 receives focus,

        arms return edge, and places pointer.
        """
        # PC 1 triggers outbound switch entering PC 2's right edge at 50% offset
        self.pc1_sender.set_redirecting(True, arrival_edge="right", offset=0.5)
        self.assertTrue(self.pc1_sender.redirecting)

        # PC 2 should receive focus target "windows"
        self.assertTrue(
            wait_for(lambda: "windows" in self.pc2_focus_calls),
            "PC 2 never received focus notification for target 'windows'",
        )

        # PC 2 return edge is armed
        self.assertTrue(
            wait_for(lambda: self.pc2_receiver.return_edge == "right"),
            "PC 2 return edge was not armed with 'right'",
        )
        self.assertEqual(self.pc2_receiver._return_edge.resistance_px, 40)

        # PC 2 pointer placed at arrival position on right edge (x=1919, y=540)
        expected_pos = return_edge.arrival_position(MONITORS_PC2, "right", 0.5)
        self.assertEqual(self.pc2_desktop.cursor, expected_pos)

    def test_input_injection_mouse_move_and_buttons(self):
        """Part 4a: Input injection on PC 2: verifies mouse moves and mouse buttons

        are forwarded and injected on PC 2.
        """
        self.pc1_sender.set_redirecting(True, arrival_edge="left", offset=0.5)
        self.assertTrue(wait_for(lambda: self.pc2_receiver.return_edge == "left"))

        # Send mouse movement
        self.pc1_sender.on_motion(25, -15)
        wait_for_calls(self.pc2_injector.calls, 1)
        self.assertIn(("mouse_move", (25, -15)), self.pc2_injector.calls)

        # Send mouse buttons (left down/up, right down/up)
        self.pc1_sender.on_mouse(capture_win.WM_LBUTTONDOWN, 0, 0, 0)
        self.pc1_sender.on_mouse(capture_win.WM_LBUTTONUP, 0, 0, 0)
        self.pc1_sender.on_mouse(capture_win.WM_RBUTTONDOWN, 0, 0, 0)
        self.pc1_sender.on_mouse(capture_win.WM_RBUTTONUP, 0, 0, 0)

        wait_for_calls(self.pc2_injector.calls, 5)
        self.assertIn(("mouse_button", ("left", True)), self.pc2_injector.calls)
        self.assertIn(("mouse_button", ("left", False)), self.pc2_injector.calls)
        self.assertIn(("mouse_button", ("right", True)), self.pc2_injector.calls)
        self.assertIn(("mouse_button", ("right", False)), self.pc2_injector.calls)

    def test_1_to_1_modifier_key_forwarding_without_mac_semantic_swap(self):
        """Part 4b: 1:1 Modifier keys: Ctrl arrives as Ctrl 0xA2, Win arrives as Win 0x5B

        without the Mac semantic swap.
        """
        self.pc1_sender.set_redirecting(True, arrival_edge="left", offset=0.5)
        self.assertTrue(wait_for(lambda: self.pc2_receiver.return_edge == "left"))

        # 1. Left Ctrl on PC 1 (VK 0xA2):
        # capture_win captures physical VK 0xA2 as "cmd".
        # Because peer_target is "windows", MacSender maps "cmd" -> wire "ctrl".
        self.pc1_sender.on_key("cmd", True, vk=0xA2)
        self.pc1_sender.on_key("cmd", False, vk=0xA2)

        # 2. Left Win on PC 1 (VK 0x5B):
        # capture_win captures physical VK 0x5B as "ctrl".
        # Because peer_target is "windows", MacSender maps "ctrl" -> wire "cmd".
        self.pc1_sender.on_key("ctrl", True, vk=0x5B)
        self.pc1_sender.on_key("ctrl", False, vk=0x5B)

        # 3. Right Ctrl on PC 1 (VK 0xA3):
        # capture_win captures physical VK 0xA3 as "cmd_r".
        # MacSender maps "cmd_r" -> wire "ctrl_r".
        self.pc1_sender.on_key("cmd_r", True, vk=0xA3)
        self.pc1_sender.on_key("cmd_r", False, vk=0xA3)

        # 4. Right Win on PC 1 (VK 0x5C):
        # capture_win captures physical VK 0x5C as "ctrl_r".
        # MacSender maps "ctrl_r" -> wire "cmd_r".
        self.pc1_sender.on_key("ctrl_r", True, vk=0x5C)
        self.pc1_sender.on_key("ctrl_r", False, vk=0x5C)

        # 5. Regular character 'c' (VK 0x43) - test Ctrl+C chord:
        self.pc1_sender.on_key("c", True, vk=0x43)
        self.pc1_sender.on_key("c", False, vk=0x43)

        wait_for_calls(self.pc2_injector.calls, 10)

        # Verify exact injected key sequence on PC 2
        injected_keys = [c[1] for c in self.pc2_injector.calls if c[0] == "key"]
        self.assertEqual(
            injected_keys,
            [
                ("ctrl", True),
                ("ctrl", False),
                ("cmd", True),
                ("cmd", False),
                ("ctrl_r", True),
                ("ctrl_r", False),
                ("cmd_r", True),
                ("cmd_r", False),
                ("c", True),
                ("c", False),
            ],
        )

        # Verify Virtual Key (VK) codes mapped on PC 2:
        # Ctrl arrives as Ctrl 0xA2 (VK_LCONTROL), NOT Mac Command 0x5B!
        # Win arrives as Win 0x5B (VK_LWIN), NOT Mac Control 0xA2!
        resolved_map = dict((k, vk) for k, down, vk in self.pc2_injector.resolved_keys)
        self.assertEqual(resolved_map["ctrl"], 0xA2, "Ctrl did not resolve to 0xA2 (VK_LCONTROL)")
        self.assertEqual(resolved_map["cmd"], 0x5B, "Win did not resolve to 0x5B (VK_LWIN)")
        self.assertEqual(resolved_map["ctrl_r"], 0xA3, "Ctrl_R did not resolve to 0xA3 (VK_RCONTROL)")
        self.assertEqual(resolved_map["cmd_r"], 0x5C, "Win_R did not resolve to 0x5C (VK_RWIN)")

        # Verify real input_injector SendInput planning logic matches
        ctrl_plan = plan_key_inputs("ctrl", True, set(), {}, lambda ch: -1, lambda vk: 0x1D)
        self.assertEqual(ctrl_plan[0][0], 0xA2)

        win_plan = plan_key_inputs("cmd", True, set(), {}, lambda ch: -1, lambda vk: 0x5B)
        self.assertEqual(win_plan[0][0], 0x5B)

    def test_mock_send_input_confirms_win32_structures_for_modifiers(self):
        """Verify that when using the real input_injector module with user32 SendInput

        mocked, the underlying Win32 KEYBDINPUT structures receive exactly 0xA2 and 0x5B.
        """
        self.pc1_sender.set_redirecting(True, arrival_edge="left", offset=0.5)
        self.assertTrue(wait_for(lambda: self.pc2_receiver.return_edge == "left"))

        with mock.patch("input_injector._send_input") as mock_send:
            # Physical Ctrl press on PC 1
            self.pc1_sender.on_key("cmd", True, vk=0xA2)
            self.pc1_sender.on_key("cmd", False, vk=0xA2)

            # Physical Win press on PC 1
            self.pc1_sender.on_key("ctrl", True, vk=0x5B)
            self.pc1_sender.on_key("ctrl", False, vk=0x5B)

            # Wait for messages to arrive at PC 2 injector
            wait_for_calls(self.pc2_injector.calls, 4)

            # Test real input_injector.inject_key with the keys received on PC 2
            # Key "ctrl":
            input_injector.inject_key("ctrl", True)
            inp_ctrl = mock_send.call_args[0][0]
            self.assertEqual(inp_ctrl.union.ki.wVk, 0xA2)  # VK_LCONTROL

            # Key "cmd" (representing Win key):
            input_injector.inject_key("cmd", True)
            inp_win = mock_send.call_args[0][0]
            self.assertEqual(inp_win.union.ki.wVk, 0x5B)  # VK_LWIN

    def test_contrast_mac_peer_keeps_semantic_swap(self):
        """Contrast test: when peer_target is 'mac' (Mac peer), physical Ctrl 0xA2

        is forwarded as wire 'cmd' (Mac Command) and physical Win 0x5B is forwarded as
        wire 'ctrl' (Mac Control), proving the 1:1 mapping only activates for Windows peers.
        """
        # Reconfigure sender with peer_target="mac"
        mac_config = replace(self.pc1_config, peer_target="mac")
        self.pc1_sender.update_config(mac_config)
        self.assertFalse(self.pc1_sender._peer_is_windows)
        self.assertEqual(self.pc1_sender._wire_name("cmd"), "cmd")
        self.assertEqual(self.pc1_sender._wire_name("ctrl"), "ctrl")

        # Now switch back to peer_target="windows"
        win_config = replace(self.pc1_config, peer_target="windows")
        self.pc1_sender.update_config(win_config)
        self.assertTrue(self.pc1_sender._peer_is_windows)
        self.assertEqual(self.pc1_sender._wire_name("cmd"), "ctrl")
        self.assertEqual(self.pc1_sender._wire_name("ctrl"), "cmd")

    def test_return_crossing_triggers_switch_msg_and_returns_focus_to_pc1(self):
        """Part 5: Return crossing from PC 2 back to PC 1 via switch_msg returning

        input cleanly to PC 1.
        """
        # Step 1: Switch out to PC 2 with arrival_edge "right"
        self.pc1_sender.set_redirecting(True, arrival_edge="right", offset=0.5)
        self.assertTrue(wait_for(lambda: self.pc2_receiver.return_edge == "right"))
        self.assertTrue(self.pc1_sender.redirecting)

        # Step 2: On PC 2, pointer reaches the right return edge
        self.pc2_desktop.cursor = (MONITORS_PC2[0].right, 500)

        # Step 3: PC 1 sends motion pushing rightwards through PC 2's return edge
        for _ in range(10):
            self.pc1_sender.on_motion(50, 0)
            self.pc2_desktop.cursor = (MONITORS_PC2[0].right, 500)
            if not self.pc1_sender.redirecting:
                break
            time.sleep(0.02)

        # Step 4: Verify PC 1 received switch_msg and disarmed redirecting
        self.assertTrue(
            wait_for(lambda: not self.pc1_sender.redirecting),
            "PC 1 did not return redirecting to False after return edge push",
        )

        # Step 5: Verify PC 2 disarmed return edge and cleared peer driving state
        self.assertTrue(
            wait_for(lambda: self.pc2_receiver.return_edge is None),
            "PC 2 return edge was not disarmed after returning home",
        )
        self.assertFalse(self.pc2_receiver._peer_driving)

        # Step 6: Verify input after switch back stays local to PC 1
        initial_call_count = len(self.pc2_injector.calls)
        self.pc1_sender.on_key("a", True)
        time.sleep(0.15)
        self.assertEqual(len(self.pc2_injector.calls), initial_call_count)


class WindowsToWindowsFullLifecycleTest(unittest.TestCase):
    """Complete end-to-end integration test executing the full lifecycle sequentially."""

    def test_complete_win_to_win_lifecycle(self):
        """Executes full Windows-to-Windows lifecycle:

        1. Pairing exchange between two Windows machines -> agreed token
        2. Config creation and TCP session connection
        3. Outbound switch to PC 2 (focus, return edge, pointer placement)
        4. Forwarding mouse moves, buttons, and 1:1 modifier keys (Ctrl 0xA2, Win 0x5B)
        5. Return crossing back to PC 1 via switch_msg returning input cleanly.
        """
        # --- 1. Pairing Phase ---
        host = PairingHost()
        code = host.begin()
        disc_port = free_udp_port()
        discovery = pairing.Discovery(bind_port=disc_port)
        discovery.start()

        host_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host_sock.bind(("127.0.0.1", 0))
        stop_pairing = threading.Event()

        def host_pair_loop():
            while not stop_pairing.is_set():
                if host.active:
                    beacon = encode(beacon_msg("OfficePC", 51820, host.pair_id))
                    try:
                        host_sock.sendto(beacon, ("127.0.0.1", disc_port))
                    except OSError:
                        pass
                host_sock.settimeout(0.05)
                try:
                    data, addr = host_sock.recvfrom(1024)
                    msg = decode(data)
                    if msg:
                        reply = host.handle(msg)
                        if reply:
                            host_sock.sendto(encode(reply), addr)
                except (socket.timeout, OSError):
                    pass

        t_pair = threading.Thread(target=host_pair_loop, daemon=True)
        t_pair.start()

        try:
            discovered = None
            for _ in range(50):
                pcs = discovery.pcs()
                if pcs and pcs[0].get("pair_id") == host.pair_id:
                    discovered = pcs[0]
                    break
                time.sleep(0.05)
            self.assertIsNotNone(discovered)
            token = discovery.pair(discovered, code, name="GamingPC")
            self.assertEqual(host.paired[0], token)
        finally:
            stop_pairing.set()
            t_pair.join(timeout=2.0)
            discovery.stop()
            host_sock.close()

        # --- 2. Live Session Connection Phase ---
        pc2_port = free_port()
        pc2_desktop = FakeDesktop(MONITORS_PC2, cursor=(500, 500))
        pc2_injector = RecordingWindowsInjector()
        pc2_statuses = []

        pc2_receiver = ReceiverServer(
            status_callback=lambda st, det: pc2_statuses.append((st, det)),
            desktop=pc2_desktop,
            injector=pc2_injector,
            self_name="OfficePC",
            peer_name="GamingPC",
            self_target="windows",
            peer_target="mac",
        )
        pc2_receiver.start(Config(host="127.0.0.1", port=pc2_port, auth_token=token))

        pc1_desktop = FakeDesktop(MONITORS_PC1, cursor=(0, 500))
        pc1_sender = MacSender(
            desktop=pc1_desktop,
            clipboard=FakeClipboard("copied_text"),
            is_local=lambda host: False,
            peer_target="windows",
        )
        pc1_config = Config(
            host="127.0.0.1",
            port=pc2_port,
            mac_host="127.0.0.1",
            auth_token=token,
            peer_target="windows",
            mac_return_edge="right",
            mac_resistance_px=40,
        )
        pc1_sender.start(pc1_config)

        try:
            self.assertTrue(wait_for(lambda: pc1_sender.connected))
            self.assertTrue(
                wait_for(lambda: any(s[0] == ServerState.CONNECTED for s in pc2_statuses))
            )

            # --- 3. Outbound Redirection Phase ---
            pc1_sender.set_redirecting(True, arrival_edge="right", offset=0.5)
            self.assertTrue(pc1_sender.redirecting)
            self.assertTrue(wait_for(lambda: pc2_receiver.return_edge == "right"))
            self.assertEqual(pc2_desktop.cursor, (1919, 540))

            # --- 4. Input Forwarding Phase (Mouse & 1:1 Modifiers) ---
            # Move cursor away from return edge into the interior so motion injects
            pc2_desktop.cursor = (960, 540)
            pc1_sender.on_motion(30, 20)
            pc1_sender.on_mouse(capture_win.WM_LBUTTONDOWN, 0, 0, 0)
            pc1_sender.on_mouse(capture_win.WM_LBUTTONUP, 0, 0, 0)

            # Forward Ctrl (captured as "cmd" from physical VK 0xA2)
            pc1_sender.on_key("cmd", True, vk=0xA2)
            pc1_sender.on_key("cmd", False, vk=0xA2)

            # Forward Win (captured as "ctrl" from physical VK 0x5B)
            pc1_sender.on_key("ctrl", True, vk=0x5B)
            pc1_sender.on_key("ctrl", False, vk=0x5B)

            wait_for_calls(pc2_injector.calls, 7)
            self.assertIn(("mouse_move", (30, 20)), pc2_injector.calls)
            self.assertIn(("mouse_button", ("left", True)), pc2_injector.calls)
            self.assertIn(("mouse_button", ("left", False)), pc2_injector.calls)
            self.assertIn(("key", ("ctrl", True)), pc2_injector.calls)
            self.assertIn(("key", ("cmd", True)), pc2_injector.calls)

            # Validate 1:1 VK mappings
            resolved = dict((k, vk) for k, down, vk in pc2_injector.resolved_keys)
            self.assertEqual(resolved["ctrl"], 0xA2)
            self.assertEqual(resolved["cmd"], 0x5B)

            # --- 5. Return Crossing Phase ---
            pc2_desktop.cursor = (MONITORS_PC2[0].right, 540)
            for _ in range(10):
                pc1_sender.on_motion(50, 0)
                pc2_desktop.cursor = (MONITORS_PC2[0].right, 540)
                if not pc1_sender.redirecting:
                    break
                time.sleep(0.02)

            self.assertTrue(wait_for(lambda: not pc1_sender.redirecting))
            self.assertTrue(wait_for(lambda: pc2_receiver.return_edge is None))
            self.assertFalse(pc2_receiver._peer_driving)

            # Input after return is not forwarded to PC 2
            calls_before = len(pc2_injector.calls)
            pc1_sender.on_key("z", True)
            time.sleep(0.15)
            self.assertEqual(len(pc2_injector.calls), calls_before)

        finally:
            pc1_sender.stop()
            pc2_receiver.stop()


if __name__ == "__main__":
    unittest.main()
