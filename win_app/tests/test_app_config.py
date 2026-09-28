import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app_config
import protocol
from dataclasses import replace

from app_config import ConfigError, config_from_dict, config_to_dict, default_config, migrate_legacy_config


BASE = {"host": "192.168.1.3", "port": 51820, "auth_token": "shared-token"}


class EdgeGlowConfigTests(unittest.TestCase):
    def test_defaults_on_and_round_trips(self):
        self.assertTrue(config_from_dict(dict(BASE)).edge_glow)
        config = config_from_dict({**BASE, "edge_glow": False})
        self.assertFalse(config.edge_glow)
        self.assertIs(config_to_dict(config)["edge_glow"], False)

    def test_rejects_a_non_boolean(self):
        with self.assertRaises(ConfigError):
            config_from_dict({**BASE, "edge_glow": "yes"})

    def test_style_and_colour_default_to_the_original_look_and_round_trip(self):
        config = config_from_dict(dict(BASE))
        self.assertEqual((config.glow_style, config.glow_colour), ("glow", "signal"))
        config = config_from_dict({**BASE, "glow_style": "beam", "glow_colour": "sunset"})
        saved = config_to_dict(config)
        self.assertEqual((saved["glow_style"], saved["glow_colour"]), ("beam", "sunset"))

    def test_colour_choices_are_the_shared_palettes(self):
        import tokens

        self.assertEqual(app_config.GLOW_COLOURS, tuple(tokens.PALETTES))

    def test_rejects_an_unknown_style_or_colour(self):
        for key, value in (("glow_style", "sparkle"), ("glow_colour", "tartan")):
            with self.subTest(key=key), self.assertRaises(ConfigError) as caught:
                config_from_dict({**BASE, key: value})
            self.assertIn(key, str(caught.exception))


class PeerTargetConfigTests(unittest.TestCase):
    def test_defaults_to_mac_and_round_trips(self):
        config = config_from_dict(dict(BASE))
        self.assertEqual(config.peer_target, "mac")
        self.assertEqual(config_to_dict(config)["peer_target"], "mac")

    def test_default_config_has_peer_target_mac(self):
        config = default_config()
        self.assertEqual(config.peer_target, "mac")

    def test_custom_peer_target_round_trips(self):
        config = config_from_dict({**BASE, "peer_target": "windows"})
        self.assertEqual(config.peer_target, "windows")
        self.assertEqual(config_to_dict(config)["peer_target"], "windows")

    def test_rejects_invalid_peer_target(self):
        for bad_value in (123, True, False, ["windows"], {"target": "mac"}, "linux", "unknown", ""):
            with self.subTest(bad_value=bad_value):
                with self.assertRaises(ConfigError) as caught:
                    config_from_dict({**BASE, "peer_target": bad_value})
                self.assertIn("peer_target", str(caught.exception))

    def test_persistence_to_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            config = config_from_dict({**BASE, "peer_target": "windows"})
            app_config.save_config(path, config)
            loaded = app_config.load_config(path)
            self.assertEqual(loaded.peer_target, "windows")


class MacHostConfigTests(unittest.TestCase):
    def test_custom_mac_host_persists_across_save_and_load(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            config = config_from_dict({**BASE, "mac_host": "192.168.1.50"})
            self.assertEqual(config.mac_host, "192.168.1.50")
            self.assertEqual(config_to_dict(config)["mac_host"], "192.168.1.50")
            app_config.save_config(path, config)
            loaded = app_config.load_config(path)
            self.assertEqual(loaded.mac_host, "192.168.1.50")



class MigrateLegacyConfigTests(unittest.TestCase):
    def test_copies_without_touching_the_old_file(self):
        with tempfile.TemporaryDirectory() as directory:
            old_path = Path(directory) / "OpenKB" / "config.json"
            old_path.parent.mkdir()
            old_path.write_text(json.dumps(BASE), encoding="utf-8")
            new_path = Path(directory) / "Beamer" / "config.json"
            with mock.patch.object(app_config, "default_config_path", return_value=new_path), \
                    mock.patch.object(app_config, "legacy_config_path", return_value=old_path):
                self.assertTrue(migrate_legacy_config())
                self.assertTrue(old_path.exists())
                self.assertEqual(
                    json.loads(new_path.read_text(encoding="utf-8")),
                    json.loads(old_path.read_text(encoding="utf-8")),
                )
                # A second run must not overwrite the now-existing new config.
                new_path.write_text(json.dumps({"changed": True}), encoding="utf-8")
                self.assertFalse(migrate_legacy_config())
                self.assertEqual(json.loads(new_path.read_text(encoding="utf-8")), {"changed": True})

    def test_is_a_noop_with_no_legacy_file(self):
        with tempfile.TemporaryDirectory() as directory:
            old_path = Path(directory) / "OpenKB" / "config.json"
            new_path = Path(directory) / "Beamer" / "config.json"
            with mock.patch.object(app_config, "default_config_path", return_value=new_path), \
                    mock.patch.object(app_config, "legacy_config_path", return_value=old_path):
                self.assertFalse(migrate_legacy_config())
                self.assertFalse(new_path.parent.exists())


if __name__ == "__main__":
    unittest.main()


class ArrangementTests(unittest.TestCase):
    """Which end's arrangement stands when the two disagree."""

    def test_the_newer_stamp_wins(self):
        self.assertTrue(protocol.arrangement_wins(200, 100))
        self.assertFalse(protocol.arrangement_wins(100, 200))

    def test_an_equal_stamp_changes_nothing(self):
        self.assertFalse(protocol.arrangement_wins(100, 100))

    def test_a_peer_with_no_stamp_never_beats_a_change_made_here(self):
        self.assertFalse(protocol.arrangement_wins(0, 100))
        self.assertFalse(protocol.arrangement_wins(None, 100))

    def test_two_ends_that_never_changed_it_agree(self):
        self.assertFalse(protocol.arrangement_wins(0, 0))


class LegacyTriggerTests(unittest.TestCase):
    def test_right_alt_is_a_choice_and_is_kept(self):
        # "alt_r" was once rewritten to "cmd_r" as a dead default, but it is a live entry in
        # TRIGGER_KEYS that the window offers, so a person who picked it lost it on every load.
        config = config_from_dict(
            {"host": "192.168.1.3", "port": 51820, "auth_token": "t", "trigger_key": "alt_r"}
        )
        self.assertEqual(config.trigger_key, "alt_r")

    def test_a_fresh_install_has_no_address_and_still_saves(self):
        config = default_config()
        self.assertEqual(config.host, "")
        config_to_dict(replace(config, auth_token="t"))

    def test_a_key_someone_chose_is_left_alone(self):
        config = config_from_dict(
            {"host": "192.168.1.3", "port": 51820, "auth_token": "t", "trigger_key": "shift_r"}
        )
        self.assertEqual(config.trigger_key, "shift_r")


class LegacyPortTests(unittest.TestCase):
    def test_the_old_default_port_is_moved_out_of_the_ephemeral_range(self):
        config = config_from_dict(
            {"host": "192.168.1.3", "port": protocol.LEGACY_DEFAULT_PORT, "auth_token": "t"}
        )
        self.assertEqual(config.port, protocol.DEFAULT_PORT)
        self.assertLess(protocol.DEFAULT_PORT, 49152)
        self.assertLess(protocol.PAIRING_PORT, 49152)

    def test_a_port_someone_chose_is_left_alone(self):
        config = config_from_dict({"host": "192.168.1.3", "port": 9000, "auth_token": "t"})
        self.assertEqual(config.port, 9000)

    def test_a_new_config_starts_on_the_new_port(self):
        self.assertEqual(default_config().port, protocol.DEFAULT_PORT)

    def test_loading_a_config_on_the_old_port_writes_the_move_down(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {"host": "192.168.1.3", "port": protocol.LEGACY_DEFAULT_PORT, "auth_token": "t"}
                ),
                encoding="utf-8",
            )
            self.assertEqual(app_config.load_config(path).port, protocol.DEFAULT_PORT)
            on_disk = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk["port"], protocol.DEFAULT_PORT)

