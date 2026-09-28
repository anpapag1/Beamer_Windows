"""The border between the two machines, and the OS each end believes the other runs.

Both ends exchange an edge over the link. With a Mac on the other side the two
apps deliberately use different conventions -- the Mac reports its own outward
edge, this app reports the peer's -- so one `OPPOSITE` on this side lines them
up. Two Windows PCs both run this app, so both would invert and the two ends
would end up agreeing on the same edge instead of facing each other. These tests
pin down which convention applies to which peer."""

import types
import unittest
from dataclasses import replace

try:
    import kvm_bridge_win
except ImportError:
    kvm_bridge_win = None

import app_config


class RecordingLink:
    def __init__(self):
        self.arrangements = []
        self.configs = []

    def send_arrangement(self, edge, set_at):
        self.arrangements.append((edge, set_at))

    def update_config(self, config):
        self.configs.append(config)


def make_app(**config_overrides):
    """A bare WindowsApplication: just the state `_set_arrangement` and
    `_on_arrangement` touch, with the writes recorded instead of hitting disk."""
    config = replace(app_config.default_config(), **config_overrides)
    app = types.SimpleNamespace(
        _config=config,
        sender=RecordingLink(),
        server=RecordingLink(),
        edge_choice=types.SimpleNamespace(set_value=lambda value: None),
        _persist=lambda: True,
        _reflect_look=lambda: None,
    )
    return app


@unittest.skipIf(kvm_bridge_win is None, "needs PySide6")
class ArrangementSyncTests(unittest.TestCase):
    def test_sending_my_edge_reports_it_flipped_into_the_peers_frame(self):
        app = make_app(mac_return_edge="left", peer_target="windows")
        kvm_bridge_win.WindowsApplication._set_arrangement(app, "right")
        self.assertEqual(app.sender.arrangements, [("left", app._config.arrangement_set_at)])
        self.assertEqual(app.server.arrangements, [("left", app._config.arrangement_set_at)])
        self.assertEqual(app._config.mac_return_edge, "right")

    def test_a_windows_peer_reports_its_own_edge_so_the_two_ends_face_each_other(self):
        app = make_app(mac_return_edge="right", peer_target="windows", arrangement_set_at=100)
        kvm_bridge_win.WindowsApplication._on_arrangement(app, "left", 200)
        self.assertEqual(app._config.mac_return_edge, "left")

    def test_a_mac_peer_still_needs_the_extra_flip(self):
        # The Mac sends its own outward edge, so this end has to invert it.
        app = make_app(mac_return_edge="right", peer_target="mac", arrangement_set_at=100)
        kvm_bridge_win.WindowsApplication._on_arrangement(app, "left", 200)
        self.assertEqual(app._config.mac_return_edge, "right")

    def test_a_peer_the_handshake_identified_as_windows_gets_the_windows_rule(self):
        # Config still says macOS -- the user never changed the OS picker --
        # but the sender learned the truth during the handshake.
        app = make_app(mac_return_edge="right", peer_target="mac", arrangement_set_at=100)
        app.sender._peer_is_windows = True
        kvm_bridge_win.WindowsApplication._on_arrangement(app, "left", 200)
        self.assertEqual(app._config.mac_return_edge, "left")

    def test_sync_off_neither_sends_nor_accepts(self):
        app = make_app(mac_return_edge="left", peer_target="windows", sync_arrangement=False)
        kvm_bridge_win.WindowsApplication._set_arrangement(app, "right")
        self.assertEqual(app.sender.arrangements, [])
        self.assertEqual(app.server.arrangements, [])
        self.assertEqual(app._config.mac_return_edge, "right")

        incoming = make_app(
            mac_return_edge="right",
            peer_target="windows",
            arrangement_set_at=100,
            sync_arrangement=False,
        )
        kvm_bridge_win.WindowsApplication._on_arrangement(incoming, "left", 200)
        self.assertEqual(incoming._config.mac_return_edge, "right")

    def test_an_older_arrangement_is_ignored(self):
        app = make_app(mac_return_edge="right", peer_target="windows", arrangement_set_at=500)
        kvm_bridge_win.WindowsApplication._on_arrangement(app, "left", 400)
        self.assertEqual(app._config.mac_return_edge, "right")

    def test_an_unusable_edge_name_is_dropped(self):
        app = make_app(mac_return_edge="right", peer_target="windows", arrangement_set_at=100)
        kvm_bridge_win.WindowsApplication._on_arrangement(app, "diagonal", 200)
        self.assertEqual(app._config.mac_return_edge, "right")


@unittest.skipIf(kvm_bridge_win is None, "needs PySide6")
class PeerPlatformPersistenceTests(unittest.TestCase):
    def _app(self, peer_target="mac"):
        saved = []
        config = replace(app_config.default_config(), peer_target=peer_target)
        app = types.SimpleNamespace(
            _config=config,
            sender=RecordingLink(),
            peer_target_choice=types.SimpleNamespace(set_value=lambda value: None),
            _persist=lambda: saved.append(True) or True,
        )
        return app, saved

    def test_a_windows_peer_the_welcome_named_is_written_to_config(self):
        app, saved = self._app("mac")
        kvm_bridge_win.WindowsApplication._on_peer_platform(app, "windows")
        self.assertEqual(app._config.peer_target, "windows")
        self.assertEqual(saved, [True])
        self.assertEqual(app.sender.configs, [app._config])

    def test_an_agreeing_platform_writes_nothing(self):
        app, saved = self._app("mac")
        kvm_bridge_win.WindowsApplication._on_peer_platform(app, "mac")
        self.assertEqual(saved, [])
        self.assertEqual(app.sender.configs, [])

    def test_an_unusable_platform_is_refused(self):
        app, saved = self._app("mac")
        kvm_bridge_win.WindowsApplication._on_peer_platform(app, "linux")
        self.assertEqual(app._config.peer_target, "mac")
        self.assertEqual(saved, [])


if __name__ == "__main__":
    unittest.main()
