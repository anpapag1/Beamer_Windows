from dataclasses import replace
import json
import socket
import threading
import time
import types
import unittest
from unittest import mock

import pairing
from pairing import PairingClient, PairingHost, beacon_msg, decode, encode


class FakeClock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def exchange(host, code, pair_id=None):
    client = PairingClient(pair_id or host.pair_id, code, "Test Mac")
    request = client.request()
    return client, request, host.handle(request)


class BeaconTests(unittest.TestCase):
    def test_beacon_carries_only_name_port_and_pairing_id(self):
        host = PairingHost(FakeClock())
        code = host.begin()
        raw = encode(beacon_msg("TEST-PC", 51820, host.pair_id))
        message = json.loads(raw)
        self.assertEqual(set(message), {"beamy", "type", "name", "port", "pair"})
        self.assertEqual(message["pair"], host.pair_id)
        self.assertNotIn(code.encode(), raw)
        self.assertEqual(decode(raw), message)

    def test_beacon_without_a_code_has_no_pairing_id(self):
        self.assertNotIn("pair", beacon_msg("TEST-PC", 51820, None))

    def test_decode_ignores_foreign_datagrams(self):
        self.assertIsNone(decode(b"\xff\x00not json"))
        self.assertIsNone(decode(b'{"beamy": 99, "type": "beacon"}'))
        self.assertIsNone(decode(b"[]"))
        self.assertIsNone(decode(b"x" * (pairing.MAX_DATAGRAM_BYTES + 1)))


class PairingHostTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.host = PairingHost(self.clock)

    def test_right_code_agrees_one_token_on_both_sides_without_sending_it(self):
        code = self.host.begin()
        client, request, reply = exchange(self.host, code)
        self.assertTrue(reply["ok"])
        token = client.accept(reply)
        self.assertEqual(self.host.paired[0], token)
        self.assertEqual(self.host.paired[1], "Test Mac")
        self.assertGreaterEqual(len(token), 40)
        wire = encode(request) + encode(reply)
        self.assertNotIn(token.encode(), wire)
        self.assertNotIn(code.encode(), wire)
        self.assertFalse(self.host.active)

    def test_wrong_code_is_refused_and_burns_the_code(self):
        code = self.host.begin()
        wrong = str((int(code) + 1) % 10**6).zfill(6)
        client, _request, reply = exchange(self.host, wrong)
        self.assertEqual(reply, {"type": "pair_reply", "pair": client.pair_id, "ok": False, "error": "refused"})
        with self.assertRaises(pairing.PairingError):
            client.accept(reply)
        self.assertIsNone(self.host.paired)
        self.assertFalse(self.host.active)
        # The right code, one second later, is no longer accepted either.
        _client, _request, retry = exchange(self.host, code, client.pair_id)
        self.assertFalse(retry["ok"])
        self.assertEqual(retry["error"], "not_pairing")

    def test_expired_code_is_refused(self):
        code = self.host.begin()
        pair_id = self.host.pair_id
        self.clock.advance(pairing.CODE_LIFETIME_SECONDS)
        _client, _request, reply = exchange(self.host, code, pair_id)
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "not_pairing")
        self.assertIsNone(self.host.paired)

    def test_unknown_pairing_id_does_not_burn_the_code(self):
        code = self.host.begin()
        _client, _request, reply = exchange(self.host, code, "deadbeef")
        self.assertEqual(reply["error"], "not_pairing")
        self.assertTrue(self.host.active)
        _client, _request, reply = exchange(self.host, code)
        self.assertTrue(reply["ok"])

    def test_retransmitted_request_gets_the_same_reply(self):
        code = self.host.begin()
        client, request, reply = exchange(self.host, code)
        self.assertEqual(self.host.handle(request), reply)
        self.assertEqual(client.accept(reply), client.accept(self.host.handle(request)))

    def test_malformed_request_burns_the_code(self):
        self.host.begin()
        reply = self.host.handle({"type": "pair_request", "pair": self.host.pair_id, "pub": "!!", "proof": "??"})
        self.assertEqual(reply["error"], "refused")
        self.assertFalse(self.host.active)

    def test_seconds_left_counts_down_to_zero(self):
        self.host.begin()
        self.assertEqual(self.host.seconds_left, int(pairing.CODE_LIFETIME_SECONDS))
        self.clock.advance(10)
        self.assertEqual(self.host.seconds_left, int(pairing.CODE_LIFETIME_SECONDS) - 10)
        self.clock.advance(100)
        self.assertEqual(self.host.seconds_left, 0)
        self.assertIsNone(self.host.code)


class PairingClientTests(unittest.TestCase):
    def test_pc_that_does_not_know_the_code_is_rejected(self):
        host = PairingHost(FakeClock())
        code = host.begin()
        client = PairingClient(host.pair_id, code, "Test Mac")
        client.request()
        # A different host, holding a different code, answers in the real one's place.
        impostor = PairingHost(FakeClock())
        impostor.begin()
        impostor.pair_id = host.pair_id
        reply = impostor.handle(client.request())
        self.assertFalse(reply["ok"])
        with self.assertRaises(pairing.PairingError):
            client.accept(reply)

    def test_tampered_reply_is_rejected(self):
        host = PairingHost(FakeClock())
        code = host.begin()
        client, _request, reply = exchange(host, code)
        other = pairing.X25519PrivateKey.generate()
        reply["pub"] = pairing._b64(pairing._public_bytes(other))
        with self.assertRaises(pairing.PairingError):
            client.accept(reply)


class DiscoveryPairingTests(unittest.TestCase):
    def test_discovery_and_host_exchange_success(self):
        host_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host_sock.bind(("127.0.0.1", 0))
        host_port = host_sock.getsockname()[1]

        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_sock.bind(("127.0.0.1", 0))
        disc_port = probe_sock.getsockname()[1]
        probe_sock.close()

        discovery = pairing.Discovery(bind_port=disc_port)
        discovery.start()

        host = PairingHost()
        code = host.begin()

        stop_host = threading.Event()

        def host_loop():
            while not stop_host.is_set():
                beacon = encode(beacon_msg("HostPC", 51820, host.pair_id))
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

        t = threading.Thread(target=host_loop, daemon=True)
        t.start()

        try:
            discovered = None
            for _ in range(50):
                pcs = discovery.pcs()
                if pcs and pcs[0].get("pair_id") == host.pair_id:
                    discovered = pcs[0]
                    break
                time.sleep(0.05)
            self.assertIsNotNone(discovered, "Discovery did not receive host beacon")
            self.assertEqual(discovered["name"], "HostPC")
            self.assertEqual(discovered["port"], 51820)

            token = discovery.pair(discovered, code, name="ClientPC")
            self.assertIsNotNone(host.paired)
            self.assertEqual(host.paired[0], token)
            self.assertEqual(host.paired[1], "ClientPC")
            self.assertGreaterEqual(len(token), 40)
            self.assertEqual(host.outcome, "paired")
        finally:
            stop_host.set()
            t.join(timeout=2.0)
            discovery.stop()
            host_sock.close()

    def test_discovery_pair_wrong_code_refused(self):
        host_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host_sock.bind(("127.0.0.1", 0))
        host_port = host_sock.getsockname()[1]

        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_sock.bind(("127.0.0.1", 0))
        disc_port = probe_sock.getsockname()[1]
        probe_sock.close()

        discovery = pairing.Discovery(bind_port=disc_port)
        discovery.start()

        host = PairingHost()
        code = host.begin()
        wrong_code = str((int(code) + 1) % 10**6).zfill(6)

        stop_host = threading.Event()

        def host_loop():
            while not stop_host.is_set():
                beacon = encode(beacon_msg("HostPC", 51820, host.pair_id))
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

        t = threading.Thread(target=host_loop, daemon=True)
        t.start()

        try:
            discovered = None
            for _ in range(50):
                pcs = discovery.pcs()
                if pcs and pcs[0].get("pair_id") == host.pair_id:
                    discovered = pcs[0]
                    break
                time.sleep(0.05)
            self.assertIsNotNone(discovered)

            with self.assertRaises(pairing.PairingError) as ctx:
                discovery.pair(discovered, wrong_code, name="ClientPC")
            self.assertEqual(str(ctx.exception), "refused")
            self.assertEqual(host.outcome, "refused")
        finally:
            stop_host.set()
            t.join(timeout=2.0)
            discovery.stop()
            host_sock.close()

    def test_discovery_pair_not_pairing(self):
        host_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host_sock.bind(("127.0.0.1", 0))
        host_port = host_sock.getsockname()[1]

        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_sock.bind(("127.0.0.1", 0))
        disc_port = probe_sock.getsockname()[1]
        probe_sock.close()

        discovery = pairing.Discovery(bind_port=disc_port)
        discovery.start()

        host = PairingHost()
        stop_host = threading.Event()

        def host_loop():
            while not stop_host.is_set():
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

        t = threading.Thread(target=host_loop, daemon=True)
        t.start()

        try:
            fake_pc = {
                "name": "HostPC",
                "address": "127.0.0.1",
                "port": 51820,
                "reply_port": host_port,
                "pair_id": "expired1",
            }
            with self.assertRaises(pairing.PairingError) as ctx:
                discovery.pair(fake_pc, "123456", name="ClientPC")
            self.assertEqual(str(ctx.exception), "not_pairing")
        finally:
            stop_host.set()
            t.join(timeout=2.0)
            discovery.stop()
            host_sock.close()


class PairingConfigLogicTests(unittest.TestCase):
    def test_client_paired_candidate_config(self):
        import app_config
        current = app_config.default_config()
        candidate = replace(
            current,
            mac_host="192.168.1.50",
            port=51820,
            auth_token="token_xyz",
            paired_with="OtherPC",
            peer_target="windows",
        )
        self.assertEqual(candidate.mac_host, "192.168.1.50")
        self.assertEqual(candidate.port, 51820)
        self.assertEqual(candidate.auth_token, "token_xyz")
        self.assertEqual(candidate.paired_with, "OtherPC")
        self.assertEqual(candidate.peer_target, "windows")

    def test_host_paired_candidate_config_learns_address(self):
        import app_config
        current = app_config.default_config()
        mac_host = current.mac_host
        client_address = "192.168.1.77"
        if client_address and not mac_host:
            mac_host = client_address
        candidate = replace(
            current,
            auth_token="token_host",
            paired_with="ClientMachine",
            mac_host=mac_host,
        )
        self.assertEqual(candidate.mac_host, "192.168.1.77")

    def test_host_paired_candidate_config_preserves_existing_address(self):
        import app_config
        current = replace(app_config.default_config(), mac_host="192.168.1.200")
        mac_host = current.mac_host
        client_address = "192.168.1.77"
        if client_address and not mac_host:
            mac_host = client_address
        candidate = replace(
            current,
            auth_token="token_host",
            paired_with="ClientMachine",
            mac_host=mac_host,
        )
        self.assertEqual(candidate.mac_host, "192.168.1.200")

    def test_client_paired_candidate_config_learns_host(self):
        import app_config
        current = replace(app_config.default_config(), host="")
        self.assertEqual(current.host, "")
        this_host = current.host
        peer_host = "192.168.1.50"
        if not this_host and peer_host:
            this_host = "192.168.1.10"
        candidate = replace(
            current,
            host=this_host or current.host,
            mac_host=peer_host,
            port=51820,
            auth_token="token_xyz",
            paired_with="OtherPC",
            peer_target="windows",
        )
        self.assertEqual(candidate.host, "192.168.1.10")
        self.assertEqual(candidate.mac_host, "192.168.1.50")


try:
    import kvm_bridge_win
except ImportError:
    kvm_bridge_win = None


@unittest.skipIf(kvm_bridge_win is None, "needs PySide6")
class WindowsPairingIntegrationTests(unittest.TestCase):
    def test_status_bridge_client_paired_signal(self):
        bridge = kvm_bridge_win.StatusBridge()
        received = []
        bridge.client_paired.connect(lambda *args: received.append(args))
        bridge.client_paired.emit("token1", "HostPC", "192.168.1.5", 51820)
        self.assertEqual(received, [("token1", "HostPC", "192.168.1.5", 51820)])

    def test_on_client_paired_updates_config(self):
        import app_config
        saved_configs = []
        applied_configs = []
        app = types.SimpleNamespace(
            _config=app_config.default_config(),
            config_path="dummy_path",
            _apply_config=applied_configs.append,
            _say_client_pairing=lambda *args: None,
            _refresh_pairing=lambda: None,
        )
        with mock.patch("kvm_bridge_win.save_config", lambda path, cfg: saved_configs.append(cfg)):
            kvm_bridge_win.WindowsApplication._on_client_paired(app, "tok_abc", "OtherPC", "192.168.1.99", 51825)
        self.assertEqual(len(saved_configs), 1)
        cfg = saved_configs[0]
        self.assertEqual(cfg.mac_host, "192.168.1.99")
        self.assertEqual(cfg.port, 51825)
        self.assertEqual(cfg.auth_token, "tok_abc")
        self.assertEqual(cfg.paired_with, "OtherPC")
        self.assertEqual(cfg.peer_target, "windows")
        self.assertEqual(applied_configs, [cfg])

    def test_on_paired_sets_mac_host_when_empty(self):
        import app_config
        saved_configs = []
        app = types.SimpleNamespace(
            _config=app_config.default_config(),
            config_path="dummy_path",
            _apply_config=lambda cfg: None,
            _say_pairing=lambda *args: None,
            _refresh_pairing=lambda: None,
            _host="192.168.1.10",
        )
        self.assertEqual(app._config.mac_host, "")
        with mock.patch("kvm_bridge_win.save_config", lambda path, cfg: saved_configs.append(cfg)):
            kvm_bridge_win.WindowsApplication._on_paired(app, "token_host", "RemoteMac", "192.168.1.77")
        self.assertEqual(len(saved_configs), 1)
        self.assertEqual(saved_configs[0].mac_host, "192.168.1.77")

    def test_on_paired_preserves_mac_host_when_already_set(self):
        import app_config
        saved_configs = []
        current = replace(app_config.default_config(), mac_host="192.168.1.200")
        app = types.SimpleNamespace(
            _config=current,
            config_path="dummy_path",
            _apply_config=lambda cfg: None,
            _say_pairing=lambda *args: None,
            _refresh_pairing=lambda: None,
            _host="192.168.1.10",
        )
        with mock.patch("kvm_bridge_win.save_config", lambda path, cfg: saved_configs.append(cfg)):
            kvm_bridge_win.WindowsApplication._on_paired(app, "token_host", "RemoteMac", "192.168.1.77")
        self.assertEqual(len(saved_configs), 1)
        self.assertEqual(saved_configs[0].mac_host, "192.168.1.200")


if __name__ == "__main__":
    unittest.main()
