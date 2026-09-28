import argparse
import ctypes
from dataclasses import replace
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from typing import Optional

from PySide6.QtCore import QEvent, QObject, QRectF, QSize, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QKeySequence, QPainter, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSlider,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from app_config import (
    Config,
    ConfigError,
    TRIGGER_KEYS,
    TRIGGER_VKS,
    UNRECORDABLE_TRIGGER_VKS,
    default_config,
    default_config_path,
    load_config,
    migrate_legacy_config,
    save_config,
)
import autostart_win
import capture_win
import desktop_win
from edge_glow import EdgeGlow, GlowPreview as EdgeGlowPreview, PreviewLoop
import firewall_win
import ignored
import pairing
from pairing import PAIRING_PORT, Announcer, Discovery, local_address_towards
import pages_win
import protocol
from receiver import ReceiverServer, ServerState
import return_edge
import sender
from sender import MacSender
import theme
import tokens
import widgets

LOGGER = logging.getLogger(__name__)

# The repo-root VERSION file is the one place the version is set; build.spec bundles it.
try:
    VERSION = (Path(getattr(sys, "_MEIPASS", None) or Path(__file__).resolve().parent.parent) / "VERSION").read_text().strip()
except OSError:
    VERSION = "dev"

HOME_PAGE = "https://kalkmancode.co.uk/beamer"
HOME_PAGE_TEXT = "kalkmancode.co.uk/beamer"

IDLE_CODE = "––– –––"
PAIR_HINT = "Press Pair a Mac, then type this code into Beamer on the Mac."

STATUS_TITLES = {
    ServerState.STOPPED: "Receiver stopped",
    ServerState.WAITING: "Waiting for your Mac",
    ServerState.CONNECTED: "Mac connected",
    ServerState.ERROR: "Receiver needs attention",
}

# The short word beside the sidebar's link dot -- STATUS_TITLES is a sentence, this is one word.
SIDEBAR_LINK_WORDS = {
    ServerState.STOPPED: "Stopped",
    ServerState.WAITING: "Waiting",
    ServerState.CONNECTED: "Linked",
    ServerState.ERROR: "Error",
}

HEADING_ROLE = {
    "signal": "heading",
    "off": "heading",
    "amber": "heading",
    "fault": "heading-fault",
}

EDGE_CHOICES = (("left", "Left"), ("right", "Right"), ("top", "Top"), ("bottom", "Bottom"))
CORNER_CHOICES = (
    ("top_left", "Top-left"),
    ("top_right", "Top-right"),
    ("bottom_left", "Bottom-left"),
    ("bottom_right", "Bottom-right"),
)
TRIGGER_STYLE_CHOICES = (("double_tap", "Double-tap"), ("hold", "Hold"))
MODIFIER_STYLE_CHOICES = (("semantic", "Semantic"), ("positional", "Positional"))
MODIFIER_NOTES = {
    "semantic": "Ctrl arrives on the Mac as Command and the Windows key as Control, so Ctrl+C "
    "copies there too.",
    "positional": "Each key arrives as the Mac key in the same place: Ctrl as Control, the Windows "
    "key as Command.",
}
FULL_SCREEN_CHECK_MS = 1000
GLOW_STYLE_CHOICES = (("glow", "Glow"), ("beam", "Beam"))
GLOW_COLOUR_CHOICES = (
    ("signal", "Signal"),
    ("colourful", "Colourful"),
    ("ocean", "Ocean"),
    ("sunset", "Sunset"),
    ("mono", "Mono"),
)
# How long a dragged slider waits, still, before the value it settled on is written to disk.
SETTLE_MS = 300


def asset_path(name: str) -> Path:
    """Locate a bundled asset, honouring PyInstaller's onefile extraction dir."""
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    else:
        base = Path(__file__).resolve().parent
    return base / name


ICON_PATH = asset_path("Beamer.ico")


def configure_logging() -> Optional[Path]:
    candidates = [default_config_path().parent, Path(tempfile.gettempdir()) / "Beamer"]
    for directory in candidates:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            log_path = directory / "Beamer.log"
            handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(message)s"))
            root_logger = logging.getLogger()
            # BEAMER_DEBUG=1 logs every injected key by name, which is the only
            # way to tell a key the Mac never sent from one Windows swallowed.
            root_logger.setLevel(logging.DEBUG if os.environ.get("BEAMER_DEBUG") else logging.INFO)
            root_logger.addHandler(handler)
            return log_path
        except OSError:
            continue
    logging.basicConfig(level=logging.INFO)
    return None


def status_icon(state: ServerState, size: int = 64) -> QPixmap:
    """The shipped colour mark with the state dot over its lower right corner, as Vernier's tray
    table draws it: signal connected, amber waiting, fault needs attention, off stopped."""
    # Ratio pinned to 1: the plain pixmap(size, size) comes back at the screen's scale (96px at
    # 150%), which once failed a width check and left the tray showing only the dot.
    pixmap = QIcon(str(ICON_PATH)).pixmap(QSize(size, size), 1.0)
    if pixmap.isNull() or pixmap.width() != size:
        pixmap = QPixmap(size, size)
        pixmap.fill(QColor(theme.colour("panel")))
    unit = size / 16
    dot = 6 * unit
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(theme.colour("ground")))
    painter.drawEllipse(QRectF(size - dot - 2 * unit, size - dot - 2 * unit, dot + 2 * unit, dot + 2 * unit))
    painter.setBrush(QColor(theme.state_colour(state.value.lower())))
    painter.drawEllipse(QRectF(size - dot - unit, size - dot - unit, dot, dot))
    painter.end()
    return pixmap


class StatusBridge(QObject):
    """Marshals receiver-thread status callbacks onto the GUI thread."""

    changed = Signal(object, str)
    pressure = Signal(str, float, bool)
    firewall = Signal(object)
    paired = Signal(str, str, str)
    client_paired = Signal(str, str, str, int)
    # The other direction: this PC's own input going to the Mac.
    sending = Signal(bool, str)
    redirecting = Signal(bool)
    focus = Signal(str)
    learned = Signal(str, object, object)
    # Either link, telling us the two machines' arrangement changed at the other end.
    arrangement = Signal(str, int)
    alert = Signal(str, str)
    mac_learned = Signal(str)


class WindowsApplication(QWidget):
    def __init__(self, config_path: Path) -> None:
        super().__init__()
        self.config_path = config_path
        self._status_lock = threading.RLock()
        self._status = ServerState.STOPPED
        self._status_detail = "Initialising"
        self._config = None
        self._closing = False
        self._page = "overview"
        self._apply_serial = 0
        self.bridge = StatusBridge()
        self.bridge.changed.connect(self._on_status)
        self.bridge.pressure.connect(self._on_pressure)
        self.bridge.firewall.connect(self._on_firewall)
        self.bridge.paired.connect(self._on_paired)
        self.bridge.client_paired.connect(self._on_client_paired)
        self.bridge.sending.connect(self._on_sending)
        self.bridge.redirecting.connect(self._on_redirecting)
        self.bridge.focus.connect(self._on_focus)
        self.bridge.learned.connect(self._on_learned)
        self.bridge.arrangement.connect(self._on_arrangement)
        # Announces this PC from launch, configured or not: pairing is how a fresh install
        # gets its token, so it cannot wait for the receiver to be listening.
        self.announcer = Announcer(self._announced_port, self.bridge.paired.emit, logger=LOGGER)
        self.discovery = pairing.Discovery(logger=LOGGER)
        self.discovery.start()
        self._pairing_client_active = False
        self._discovered_pcs_key = None
        self._code_shown = False
        self._firewall_advice: Optional[firewall_win.Advice] = None
        self._firewall_status: Optional[firewall_win.FirewallStatus] = None
        self._firewall_tone: Optional[str] = None
        self._firewall_busy = False
        self._firewall_again = False
        self._firewall_auto_repaired = False
        self._host = default_config().host
        self._last_seen_state: Optional[ServerState] = None
        self.glow: Optional[EdgeGlow] = None
        self.server = ReceiverServer(
            self._set_status,
            pressure_callback=self.bridge.pressure.emit,
            focus_callback=self.bridge.focus.emit,
            peer_callback=self.bridge.learned.emit,
            arrangement_callback=self.bridge.arrangement.emit,
        )
        # The second link, outwards: this PC's keyboard and mouse on the Mac.
        self.sender = MacSender(
            status_callback=self.bridge.sending.emit,
            redirect_callback=self.bridge.redirecting.emit,
            pressure_callback=self.bridge.pressure.emit,
            arrangement_callback=self.bridge.arrangement.emit,
        )
        self.sender.send_peer_home = self.server.send_home
        self.sender.on_alert = self.bridge.alert.emit
        self.sender.on_mac_learned = self.bridge.mac_learned.emit
        self.bridge.alert.connect(self._on_alert)
        self.bridge.mac_learned.connect(self._on_mac_learned)
        self.hooks = capture_win.Hooks(self._on_hook_key, self.sender.on_mouse, self.sender.on_motion)
        self._trigger = capture_win.Trigger()
        self._sending_detail = "Not connected to the Mac"
        try:
            self._config = load_config(config_path)
            self._host = self._config.host
            self._status = ServerState.WAITING
            self._status_detail = f"Ready on TCP port {self._config.port}"
        except ConfigError as exc:
            LOGGER.info("Configuration is not ready: %s", exc)
            self._status = ServerState.ERROR
            self._status_detail = "Enter a shared token to finish setup"

        self.setWindowTitle("Beamer")
        self.resize(820, 720)
        self.setMinimumSize(*tokens.MIN_WINDOW["windows"])
        self.setWindowIcon(QIcon(str(ICON_PATH)))
        self.preview_loop = PreviewLoop(self)
        self._build_window()
        self._apply_theme()
        self._build_tray()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(250)
        self.refresh_timer.timeout.connect(self._refresh_window)
        self.refresh_timer.start()
        self.full_screen_timer = QTimer(self)
        self.full_screen_timer.setInterval(FULL_SCREEN_CHECK_MS)
        self.full_screen_timer.timeout.connect(self._check_full_screen)
        self.full_screen_timer.start()
        # Otherwise the heading, the "Input:"/"Now:" readouts and the sidebar dots sit blank
        # for the first 250ms every launch, waiting for the timer's first tick.
        self._refresh_window()
        # start() triggers the first read through the WAITING transition; without a config the
        # receiver never starts, so the row would otherwise say "Checking" forever.
        if self._config is None:
            self._check_firewall()

    # -- window and pages -----------------------------------------------------------------

    def _build_window(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(0)

        self.sidebar = widgets.Sidebar(
            # Two lines: one, at the sidebar's fixed width, cuts the address off.
            pages_win.PAGES, self._select_page, foot=f"Beamer {VERSION}\n{HOME_PAGE_TEXT}", on_foot=self.open_home_page
        )
        self.sidebar.setFixedWidth(theme.SIDEBAR_WIDTH)
        row_layout.addWidget(self.sidebar)
        row_layout.addWidget(widgets.rule())

        self.stack = QStackedWidget()
        row_layout.addWidget(self.stack, 1)
        outer.addWidget(row, 1)

        footer = QFrame()
        footer.setProperty("vernier", "commit")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(16, 10, 16, 10)
        footer_layout.addWidget(
            widgets.label("Closing this window keeps Beamer running in the tray.", "note", wrap=True)
        )
        outer.addWidget(footer)

        current = self._config or default_config()
        builders = {
            "overview": self._overview_page,
            "crossing": self._crossing_page,
            "design": self._design_page,
            "keyboard": self._keyboard_page,
            "pairing": self._pairing_page,
            "connection": self._connection_page,
            "firewall": self._firewall_page,
        }
        self._page_indexes: dict = {}
        for key, name, purpose in pages_win.PAGES:
            scroll, layout = self._page_shell(name, purpose)
            builders[key](layout, current)
            layout.addStretch(1)
            self._page_indexes[key] = self.stack.addWidget(scroll)

        for index, key in enumerate(pages_win.KEYS[:9]):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{index + 1}"), self)
            shortcut.activated.connect(lambda k=key: self._select_page(k))

        self._select_page("overview")

    def _page_shell(self, title: str, purpose: str):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        # Nothing scrolls sideways, at any width.
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        page = QWidget()
        page.setProperty("vernier", "plain")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)
        heading = widgets.label(title.upper(), "heading")
        heading.setFont(theme.font(theme.HEADING, 700))
        layout.addWidget(heading)
        layout.addWidget(widgets.label(purpose, "note", wrap=True))
        scroll.setWidget(page)
        return scroll, layout

    def _select_page(self, key: str) -> None:
        index = self._page_indexes.get(key)
        if index is None:
            return
        self._page = key
        self.stack.setCurrentIndex(index)
        self.sidebar.select(key)
        if key != "keyboard":
            self.ignored_recorder.cancel()
            self.trigger_recorder.cancel()
        self._run_previews()

    # -- Overview ---------------------------------------------------------------------------

    def _overview_page(self, layout, current) -> None:
        layout.addWidget(self._link_module())
        layout.addWidget(self._input_module())
        layout.addWidget(self._daily_module(current))

    def _link_module(self) -> QWidget:
        module = widgets.Module("Link")
        led_row = QHBoxLayout()
        led_row.setSpacing(8)
        self.led = widgets.Led()
        led_row.addWidget(self.led, 0, Qt.AlignmentFlag.AlignVCenter)
        led_row.addStretch(1)
        module.body.addLayout(led_row)
        self.status_heading = widgets.label("", "heading", wrap=True)
        self.status_heading.setFont(theme.font(theme.HEADING, 700))
        module.body.addWidget(self.status_heading)
        self.status_detail = widgets.label("", "note", wrap=True)
        module.body.addWidget(self.status_detail)
        where_row = QHBoxLayout()
        where_row.setSpacing(6)
        where_row.addWidget(widgets.label("Input:", "note"))
        self.location_readout = widgets.label("", "readout", wrap=True)
        where_row.addWidget(self.location_readout, 1)
        module.body.addLayout(where_row)
        # Shown only while there is a figure: the trip is measured while input is on the Mac.
        self.round_trip_row = QWidget()
        trip_row = QHBoxLayout(self.round_trip_row)
        trip_row.setContentsMargins(0, 0, 0, 0)
        trip_row.setSpacing(6)
        trip_row.addWidget(widgets.label("Round trip:", "note"))
        self.round_trip_readout = widgets.label("", "readout", wrap=True)
        trip_row.addWidget(self.round_trip_readout, 1)
        self.round_trip_row.setVisible(False)
        module.body.addWidget(self.round_trip_row)
        return module

    def _input_module(self) -> QWidget:
        """The Mac's two everyday buttons: send input across without the shortcut or an edge, and
        hold the edges for a while."""
        module = widgets.Module("Keyboard and mouse")
        self.redirect_button = QPushButton("Send input to your Mac")
        self.redirect_button.setProperty("vernier", "primary")
        self.redirect_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.redirect_button.clicked.connect(self.toggle_redirect)
        module.body.addWidget(self.redirect_button)
        self.pause_button = QPushButton("Pause crossing")
        self.pause_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.pause_button.clicked.connect(self.toggle_pause)
        module.body.addWidget(self.pause_button)
        self.crossing_state = widgets.label("", "note", wrap=True)
        module.body.addWidget(self.crossing_state)
        return module

    def toggle_redirect(self) -> None:
        self.sender.toggle()

    def toggle_pause(self) -> None:
        self.sender.crossing_paused = not self.sender.crossing_paused
        self._refresh_window()

    def _crossing_state_sentence(self) -> str:
        methods = set(self._config.crossing_methods) if self._config is not None else set()
        if not methods & {"edge", "corner"}:
            return "Only the shortcut is switched on; there is nothing to pause."
        if self.sender.crossing_paused:
            return "Paused. The edge and corner do nothing until you resume; the shortcut still works."
        if self.sender.full_screen_app is not None:
            return (
                f"Off while {self.sender.full_screen_app} is full screen, so the pointer stays put at "
                "the edges; the shortcut still works."
            )
        return "On. Pause it to lean on an edge without switching."

    def _check_full_screen(self) -> None:
        """The Mac's rule: a full-screen app in front holds the edges, the shortcut still works.
        A failure stops the check for the run rather than logging once a second."""
        try:
            self.sender.full_screen_app = desktop_win.full_screen_app()
        except Exception:
            self.sender.full_screen_app = None
            self.full_screen_timer.stop()
            LOGGER.exception("Could not tell whether an app is full screen; crossing stays on")

    def _on_alert(self, title: str, message: str) -> None:
        if self._closing:
            return
        if message.startswith("Cannot switch"):
            QApplication.beep()
        self.tray.showMessage(title, message, QIcon(str(ICON_PATH)), 4000)

    def _on_mac_learned(self, address: str) -> None:
        if self._config is None or self._config.mac_hardware_address == address:
            return
        self._config.mac_hardware_address = address
        self._persist()

    def _daily_module(self, current: Config) -> QWidget:
        module = widgets.Module("Every day")
        self.allow_switch = widgets.Switch("Let your Mac drive this PC")
        self.allow_switch.setFont(theme.font(theme.TYPE["body"]))
        self.allow_switch.setChecked(current.allow_mac_to_drive)
        self.allow_switch.toggled.connect(self._set_allow_drive)
        module.body.addWidget(self.allow_switch)
        self.send_switch = widgets.Switch("Send this PC's keyboard and mouse to your Mac")
        self.send_switch.setFont(theme.font(theme.TYPE["body"]))
        self.send_switch.setChecked(current.send_to_mac)
        self.send_switch.toggled.connect(self._toggle_sending)
        module.body.addWidget(self.send_switch)
        self.send_hint = widgets.label("", "note", wrap=True)
        self.send_hint.setVisible(False)
        module.body.addWidget(self.send_hint)
        self.logon_switch = widgets.Switch("Start Beamer when you sign in")
        self.logon_switch.setFont(theme.font(theme.TYPE["body"]))
        exe = autostart_win.installed_exe()
        try:
            self.logon_switch.setChecked(exe is not None and autostart_win.is_enabled())
        except OSError:
            LOGGER.exception("Could not read the logon task")
        self.logon_switch.setEnabled(exe is not None)
        self.logon_switch.toggled.connect(self._set_start_at_logon)
        module.body.addWidget(self.logon_switch)
        self.logon_hint = widgets.label(
            "In the tray, with no window." if exe else "Only the installed app can start at sign-in.",
            "note",
            wrap=True,
        )
        module.body.addWidget(self.logon_hint)
        if self._config is None:
            self.allow_switch.setEnabled(False)
            self.send_switch.setEnabled(False)
        return module

    def _set_allow_drive(self, enabled: bool) -> None:
        """Replaces the old Start/Stop receiver button: this switch is what persists."""
        if self._config is None:
            return
        self._config.allow_mac_to_drive = bool(enabled)
        self._persist()
        try:
            if enabled:
                self.server.start(self._config)
            else:
                self.server.stop()
        except Exception as exc:
            LOGGER.exception("Receiver action failed")
            self._set_status(ServerState.ERROR, f"Receiver failed: {exc}")

    def _set_start_at_logon(self, enabled: bool) -> None:
        exe = autostart_win.installed_exe()
        if exe is None:
            return
        try:
            autostart_win.set_enabled(enabled, exe)
        except OSError as exc:
            LOGGER.warning("Could not change the logon task: %s", exc)
            self.logon_switch.blockSignals(True)
            self.logon_switch.setChecked(not enabled)
            self.logon_switch.blockSignals(False)
            self.logon_hint.setText(f"Windows refused: {exc}")
            return
        self.logon_hint.setText("In the tray, with no window.")

    def _toggle_sending(self, enabled: bool) -> None:
        """Takes effect at once: it decides whether this PC's own keyboard is being
        watched, which is not something to leave a person guessing about."""
        if self._config is None:
            return
        self._config.send_to_mac = bool(enabled)
        self._persist()
        if enabled:
            self._start_sending(self._config)
        else:
            self._stop_sending()

    # -- Crossing -----------------------------------------------------------------------------

    def _crossing_page(self, layout, current: Config) -> None:
        layout.addWidget(self._ways_module(current))
        layout.addWidget(self._resistance_module(current))

    def _ways_module(self, current: Config) -> QWidget:
        module = widgets.Module("Ways in")
        self.way_boxes: dict = {}
        for value, text in (("edge", "Edge"), ("corner", "Corner"), ("shortcut", "Shortcut")):
            box = QCheckBox(text)
            box.setChecked(value in current.crossing_methods)
            box.toggled.connect(self._ways_changed)
            module.body.addWidget(box)
            self.way_boxes[value] = box

        module.body.addWidget(
            widgets.label(
                "Which edge of this PC leads to your Mac. It is the same border both ways, so "
                "setting it here moves it on the Mac too.",
                "note",
                wrap=True,
            )
        )
        module.body.addWidget(widgets.label("Edge", "key"))
        self.edge_choice = widgets.Choice(
            EDGE_CHOICES, columns=4, current=current.mac_return_edge or "right", on_change=self._set_arrangement
        )
        module.body.addWidget(self.edge_choice.view)

        module.body.addWidget(widgets.label("Corner", "key"))
        self.corner_choice = widgets.Choice(
            CORNER_CHOICES, columns=2, current=current.crossing_corner, on_change=self._set_corner
        )
        module.body.addWidget(self.corner_choice.view)
        self.corner_choice.set_enabled("corner" in current.crossing_methods)

        self.dragging_switch = widgets.Switch("Never while dragging")
        self.dragging_switch.setFont(theme.font(theme.TYPE["body"]))
        self.dragging_switch.setChecked(current.block_while_dragging)
        self.dragging_switch.toggled.connect(self._set_block_while_dragging)
        module.body.addWidget(self.dragging_switch)

        now_row = QHBoxLayout()
        now_row.setSpacing(6)
        # Named, not just "Now": this line is the Mac's half of the border --
        # the edge and push it asks for when it is the one sending -- and under
        # a column of this PC's own controls it reads as one of them otherwise.
        now_row.addWidget(widgets.label("Your Mac asks for:", "note"))
        self.return_readout = widgets.label("", "readout", wrap=True)
        now_row.addWidget(self.return_readout, 1)
        module.body.addLayout(now_row)
        return module

    def _ways_changed(self, *_ignored) -> None:
        if self._config is None:
            return
        self._config.crossing_methods = [value for value, box in self.way_boxes.items() if box.isChecked()]
        self._persist()
        self.corner_choice.set_enabled(self.way_boxes["corner"].isChecked())
        self.sender.update_config(self._config)

    def _set_arrangement(self, pc_edge: str) -> None:
        """The edge of THIS PC that leads to the Mac -- one border, walked either way. Not an
        ordinary save: both machines have to agree on it, so this end's change is timestamped
        and sent over whichever link is up."""
        if self._config is None or pc_edge == self._config.mac_return_edge:
            return
        self._config.mac_return_edge = pc_edge
        self._config.arrangement_set_at = int(time.time())
        self._persist()
        mac_edge = return_edge.OPPOSITE[pc_edge]
        self.sender.send_arrangement(mac_edge, self._config.arrangement_set_at)
        self.server.send_arrangement(mac_edge, self._config.arrangement_set_at)
        self.sender.update_config(self._config)
        self._reflect_look()

    def _set_block_while_dragging(self, enabled: bool) -> None:
        if self._config is None:
            return
        self._config.block_while_dragging = bool(enabled)
        self._persist()
        self.sender.update_config(self._config)

    def _set_corner(self, corner: str) -> None:
        if self._config is None:
            return
        self._config.crossing_corner = corner
        self._persist()
        self.sender.update_config(self._config)

    def _on_arrangement(self, mac_edge: str, set_at: int) -> None:
        """The Mac changed the arrangement, over either link. `mac_edge` is always the edge of
        the MAC that leads here; an arrival older than what this end already holds is ignored."""
        if self._config is None:
            return
        if self._config.arrangement_set_at and not protocol.arrangement_wins(set_at, self._config.arrangement_set_at):
            LOGGER.info("Ignoring an older arrangement from the Mac (%s vs %s)", set_at, self._config.arrangement_set_at)
            return
        pc_edge = return_edge.OPPOSITE.get(mac_edge)
        if pc_edge is None:
            return
        self._config.mac_return_edge = pc_edge
        self._config.arrangement_set_at = int(set_at)
        self._persist()
        self.sender.update_config(self._config)
        self.edge_choice.set_value(pc_edge)
        self._reflect_look()

    def _resistance_module(self, current: Config) -> QWidget:
        module = widgets.Module("Resistance")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.resistance_slider = QSlider(Qt.Orientation.Horizontal)
        self.resistance_slider.setRange(0, 500)
        self.resistance_slider.setValue(current.crossing_resistance_px)
        self.resistance_slider.valueChanged.connect(self._resistance_changed)
        row.addWidget(self.resistance_slider, 1)
        self.resistance_readout = widgets.label(f"{current.crossing_resistance_px} px", "readout")
        row.addWidget(self.resistance_readout)
        module.body.addLayout(row)
        self.resistance_hint = widgets.label("", "note", wrap=True)
        module.body.addWidget(self.resistance_hint)
        self._update_resistance_hint(current.crossing_resistance_px)
        return module

    def _resistance_changed(self, value: int) -> None:
        self.resistance_readout.setText(f"{value} px")
        self._update_resistance_hint(value)
        if self._config is None:
            return
        self._config.crossing_resistance_px = int(value)
        self.sender.update_config(self._config)
        self._debounce_save()

    def _update_resistance_hint(self, value: int) -> None:
        text = (
            "Switches the moment the pointer touches the edge."
            if value == 0
            else "How far to push past the edge before it gives."
        )
        if text != self.resistance_hint.text():
            self.resistance_hint.setText(text)

    # -- Keyboard -----------------------------------------------------------------------------

    def _keyboard_page(self, layout, current: Config) -> None:
        layout.addWidget(self._shortcut_module(current))
        layout.addWidget(self._ignored_module(current))
        layout.addWidget(self._modifier_module(current))

    def _modifier_module(self, current: Config) -> QWidget:
        module = widgets.Module("Modifier keys")
        self.modifier_choice = widgets.Choice(
            MODIFIER_STYLE_CHOICES, columns=2, current=current.modifier_style, on_change=self._set_modifier_style
        )
        module.body.addWidget(self.modifier_choice.view)
        self.modifier_note = widgets.label(MODIFIER_NOTES[current.modifier_style], "note", wrap=True)
        module.body.addWidget(self.modifier_note)
        return module

    def _set_modifier_style(self, value: str) -> None:
        self.modifier_note.setText(MODIFIER_NOTES[value])
        if self._config is None:
            return
        self._config.modifier_style = value
        self._persist()
        self.sender.update_config(self._config)

    def _ignored_module(self, current: Config) -> QWidget:
        module = widgets.Module("Stays on this PC")
        self.ignored_note = widgets.label("", "note", wrap=True)
        module.body.addWidget(self.ignored_note)
        self.ignored_list = QVBoxLayout()
        self.ignored_list.setSpacing(4)
        module.body.addLayout(self.ignored_list)
        self.ignored_recorder = widgets.InputRecorder("Add a key or button", self._record_ignored, capture_win.hook_vk)
        module.body.addWidget(self.ignored_recorder)
        self._show_ignored(list(current.ignored_inputs))
        return module

    def _show_ignored(self, entries: list, refused: str = "") -> None:
        while self.ignored_list.count():
            item = self.ignored_list.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        for entry in entries:
            row = QFrame()
            row.setProperty("vernier", "entry")
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(12, 6, 6, 6)
            name = widgets.label(capture_win.input_title(entry), "readout")
            row_layout.addWidget(name, 1)
            remove = QPushButton("Remove")
            remove.setProperty("vernier", "remove")
            remove.setCursor(Qt.CursorShape.PointingHandCursor)
            remove.setAccessibleName(f"Remove {capture_win.input_title(entry)}")
            remove.clicked.connect(lambda _checked=False, e=entry: self._remove_ignored(e))
            row_layout.addWidget(remove)
            self.ignored_list.addWidget(row)
        text = refused or (
            "These keep working on this PC while its input is on your Mac: a mouse's back button for "
            "this PC's browser, say, or a volume key for its speakers."
            if entries
            else "Nothing yet. Every key and button goes to your Mac while it has input. Add one to keep "
            "it here: a mouse's back button for this PC's browser, say, or a volume key for its speakers."
        )
        self.ignored_note.setText(text)
        widgets.set_role(self.ignored_note, "note-amber" if refused else "note")

    def _record_ignored(self, kind: str, value) -> None:
        if self._config is None:
            return
        entries = list(self._config.ignored_inputs)
        if kind == "key" and value == TRIGGER_VKS.get(self._config.trigger_key):
            self._show_ignored(entries, "That key is the shortcut; it always stays with Beamer.")
            return
        entry = ignored.key(value) if kind == "key" else ignored.button(value)
        if entry not in entries:
            entries.append(entry)
        self._set_ignored(entries)

    def _remove_ignored(self, entry: str) -> None:
        if self._config is None:
            return
        self._set_ignored([candidate for candidate in self._config.ignored_inputs if candidate != entry])

    def _set_ignored(self, entries: list) -> None:
        previous = self._config.ignored_inputs
        self._config.ignored_inputs = entries
        if not self._persist():
            # A list the file refuses, past ignored.MAX_ENTRIES, or a disk that would not take it:
            # the running app keeps what is saved, so the list shown is the one the next start uses.
            self._config.ignored_inputs = previous
            self._show_ignored(list(previous), "That could not be saved, so the list is unchanged.")
            return
        self.sender.update_config(self._config)
        self._show_ignored(entries)

    def _shortcut_module(self, current: Config) -> QWidget:
        module = widgets.Module("Shortcut")
        module.body.addWidget(
            widgets.label(
                "Use this key to send input to your Mac, and to bring it back.", "note", wrap=True
            )
        )
        self.trigger_recorder = widgets.InputRecorder(
            TRIGGER_KEYS.get(current.trigger_key, current.trigger_key),
            self._record_trigger,
            capture_win.hook_vk,
            keys_only=True,
        )
        self.trigger_recorder.HINT = "Click, then press the key"
        self.trigger_recorder.hint.setText(self.trigger_recorder.HINT)
        module.body.addWidget(self.trigger_recorder)
        self.trigger_note = widgets.label("", "note-amber", wrap=True)
        self.trigger_note.setVisible(False)
        module.body.addWidget(self.trigger_note)
        self.trigger_style_choice = widgets.Choice(
            TRIGGER_STYLE_CHOICES, columns=2, current=current.trigger_style, on_change=self._set_trigger_style
        )
        module.body.addWidget(self.trigger_style_choice.view)
        self.style_hint = widgets.label("", "note", wrap=True)
        module.body.addWidget(self.style_hint)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.double_tap_slider = QSlider(Qt.Orientation.Horizontal)
        # The Mac's range: the store takes 50 to 2000 ms, but only about 150 to 600 is useful.
        self.double_tap_slider.setRange(50, 1000)
        self.double_tap_slider.setValue(current.double_tap_ms)
        self.double_tap_slider.valueChanged.connect(self._double_tap_changed)
        row.addWidget(self.double_tap_slider, 1)
        self.double_tap_readout = widgets.label(f"{current.double_tap_ms} ms", "readout")
        row.addWidget(self.double_tap_readout)
        module.body.addLayout(row)
        self.double_tap_slider.setEnabled(current.trigger_style != "hold")
        self._update_style_hint(current.trigger_style)
        return module

    def _record_trigger(self, kind: str, value) -> None:
        """Any key that types nothing, as on the Mac: a modifier, a function key, a navigation
        key. A key that types a character would stop typing it, so it is refused, and said so."""
        name = None
        if kind == "key" and value not in UNRECORDABLE_TRIGGER_VKS:
            name = next((n for n, vk in TRIGGER_VKS.items() if vk == value), None)
        if name is None:
            self.trigger_note.setText(
                "That key cannot be the shortcut. Choose a modifier such as Right Ctrl, a function "
                "key, or a key like Insert or Scroll Lock."
            )
            self.trigger_note.setVisible(True)
            return
        self.trigger_note.setVisible(False)
        self.trigger_recorder.set_title(TRIGGER_KEYS[name])
        if self._config is None:
            return
        self._config.trigger_key = name
        self._persist()
        self._configure_trigger(self._config)
        if ignored.key(value) in self._config.ignored_inputs:
            # The shortcut always stays with Beamer, so it cannot also be on the stays-here list.
            self._set_ignored([entry for entry in self._config.ignored_inputs if entry != ignored.key(value)])

    def _set_trigger_style(self, value: str) -> None:
        if self._config is None:
            return
        self._config.trigger_style = value
        self._persist()
        self._configure_trigger(self._config)
        self.double_tap_slider.setEnabled(value != "hold")
        self._update_style_hint(value)

    def _update_style_hint(self, style: str) -> None:
        text = (
            "Input is on the Mac for as long as the key is held."
            if style == "hold"
            else "Tap twice to switch; tap twice again to come back."
        )
        if text != self.style_hint.text():
            self.style_hint.setText(text)

    def _double_tap_changed(self, value: int) -> None:
        self.double_tap_readout.setText(f"{value} ms")
        if self._config is None:
            return
        self._config.double_tap_ms = int(value)
        self._configure_trigger(self._config)
        self._debounce_save()

    # -- Design -------------------------------------------------------------------------------

    def _design_page(self, layout, current: Config) -> None:
        layout.addWidget(self._on_screen_module(current))
        layout.addWidget(self._edge_look_module(current))

    def _on_screen_module(self, current: Config) -> QWidget:
        module = widgets.Module("On screen")
        self.glow_toggle = widgets.Switch("Light up the edge as you push")
        self.glow_toggle.setFont(theme.font(theme.TYPE["body"]))
        self.glow_toggle.setChecked(current.edge_glow)
        self.glow_toggle.toggled.connect(self._apply_look)
        module.body.addWidget(self.glow_toggle)
        module.body.addWidget(
            widgets.label(
                "Lights the edge of this PC that leads to your Mac as you push toward it. Switched "
                "off, crossing still works. Your Mac sets how its own edge and notch look.",
                "note",
                wrap=True,
            )
        )
        return module

    def _edge_look_module(self, current: Config) -> QWidget:
        module = widgets.Module("Edge and corner")
        edge = current.mac_return_edge or "right"
        self.glow_previews = {
            style: EdgeGlowPreview(style, current.glow_colour, edge) for style, _title in GLOW_STYLE_CHOICES
        }
        for preview in self.glow_previews.values():
            self.preview_loop.add(preview)
        self.glow_style_choice = widgets.ChoiceTiles(
            [
                ("glow", "Glow", "A band of light that deepens the harder you push.", self.glow_previews["glow"]),
                ("beam", "Beam", "A thin line with a comet of light running along it.", self.glow_previews["beam"]),
            ],
            current.glow_style,
            on_change=self._apply_look,
        )
        module.body.addWidget(self.glow_style_choice.view)
        module.body.addWidget(widgets.label("Colour", "key"))
        self.glow_colour_choice = widgets.Swatches(GLOW_COLOUR_CHOICES, current.glow_colour, on_change=self._apply_look)
        module.body.addWidget(self.glow_colour_choice.view)
        self._reflect_look()
        return module

    def _apply_look(self, *_ignored) -> None:
        """The glow's switch, style and colour save and apply the moment they change. They only
        decide how this PC's edge is drawn, so the receiver has no reason to restart for them."""
        self._reflect_look()
        if self._config is None:
            return
        self._config.edge_glow = self.glow_toggle.isChecked()
        self._config.glow_style = self.glow_style_choice.value
        self._config.glow_colour = self.glow_colour_choice.value
        self._persist()
        if not self._config.edge_glow and self.glow is not None:
            self.glow.hide()

    def _reflect_look(self) -> None:
        on = self.glow_toggle.isChecked()
        self.glow_style_choice.set_enabled(on)
        self.glow_colour_choice.set_enabled(on)
        edge = (self._config.mac_return_edge if self._config is not None else "") or "right"
        for preview in self.glow_previews.values():
            preview.set_look(self.glow_colour_choice.value or "signal", edge)
        self._run_previews()

    def _run_previews(self) -> None:
        """The previews play only while someone can see them: the Design page open in a visible
        window, with the glow switched on."""
        self.preview_loop.run(
            self.isVisible() and not self.isMinimized() and self._page == "design" and self.glow_toggle.isChecked()
        )

    def _debounce_save(self) -> None:
        """A ruler being dragged writes once at the end rather than on every step."""
        self._apply_serial += 1
        serial = self._apply_serial
        QTimer.singleShot(SETTLE_MS, lambda: self._settle(serial))

    def _settle(self, serial: int) -> None:
        if serial == self._apply_serial:
            self._persist()

    def _persist(self) -> bool:
        if self._config is None:
            return False
        try:
            save_config(self.config_path, self._config)
            return True
        except (ConfigError, OSError):
            LOGGER.exception("Setting could not be saved")
            return False

    # -- Pairing --------------------------------------------------------------------------

    def _pairing_page(self, layout, current: Config) -> None:
        module = widgets.Module("Pairing code")
        head = QHBoxLayout()
        head.setSpacing(16)
        head.addWidget(module.eyebrow, 0, Qt.AlignmentFlag.AlignTop)
        self.pair_note = widgets.label("", "note", wrap=True)
        self.pair_note.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        head.addWidget(self.pair_note, 1)
        module.body.addLayout(head)
        code_row = QHBoxLayout()
        code_row.setSpacing(18)
        self.code_label = widgets.label(IDLE_CODE, "code-idle")
        self.code_label.setFont(theme.mono_font(theme.PAIRING_CODE))
        self.code_label.setAccessibleName("Pairing code")
        # The digits have no descenders, so the line box can be trimmed to the ink.
        self.code_label.setFixedHeight(round(theme.PAIRING_CODE))
        code_row.addWidget(self.code_label, 1, Qt.AlignmentFlag.AlignVCenter)
        count = QVBoxLayout()
        count.setSpacing(8)
        count.addStretch(1)
        self.count_label = widgets.label("1:00", "count-idle")
        self.count_label.setFont(theme.mono_font(theme.COUNT))
        self.count_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        count.addWidget(self.count_label, 0, Qt.AlignmentFlag.AlignRight)
        self.pair_button = QPushButton("Pair a Mac")
        self.pair_button.setProperty("vernier", "primary")
        self.pair_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.pair_button.clicked.connect(self._toggle_pairing)
        count.addWidget(self.pair_button, 0, Qt.AlignmentFlag.AlignRight)
        count.addStretch(1)
        code_row.addLayout(count)
        module.body.addLayout(code_row)
        self.drain = widgets.Drain()
        module.body.addWidget(self.drain)
        layout.addWidget(module)
        self._say_pairing(f"Paired with {current.paired_with}." if current.paired_with else PAIR_HINT, "note")

        client_module = widgets.Module("Pair with a discovered computer")
        client_head = QHBoxLayout()
        client_head.setSpacing(16)
        client_head.addWidget(client_module.eyebrow, 0, Qt.AlignmentFlag.AlignTop)
        self.client_pair_note = widgets.label("", "note", wrap=True)
        self.client_pair_status = self.client_pair_note
        self.client_pair_note.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        client_head.addWidget(self.client_pair_note, 1)
        client_module.body.addLayout(client_head)

        client_grid = QGridLayout()
        client_grid.setHorizontalSpacing(10)
        client_grid.setVerticalSpacing(10)
        client_grid.setColumnStretch(1, 1)

        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(220)
        self.discovered_combo = self.device_combo
        client_grid.addWidget(widgets.label("Discovered device", "key"), 0, 0)
        client_grid.addWidget(self.device_combo, 0, 1)

        code_box = QHBoxLayout()
        code_box.setSpacing(8)
        self.code_entry = QLineEdit()
        self.client_code_entry = self.code_entry
        self.code_entry.setPlaceholderText("6-digit code")
        self.code_entry.setMaxLength(6)
        self.code_entry.setFixedWidth(110)
        self.code_entry.setFont(theme.mono_font(theme.SIZE_ENTRY))
        self.code_entry.returnPressed.connect(self._start_client_pair)
        code_box.addWidget(self.code_entry)

        self.client_pair_button = QPushButton("Pair")
        self.pair_client_button = self.client_pair_button
        self.client_pair_button.setProperty("vernier", "primary")
        self.client_pair_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.client_pair_button.clicked.connect(self._start_client_pair)
        code_box.addWidget(self.client_pair_button)
        code_box.addStretch(1)

        client_grid.addWidget(widgets.label("Pairing code", "key"), 1, 0)
        client_grid.addLayout(code_box, 1, 1)

        client_module.body.addLayout(client_grid)
        layout.addWidget(client_module)
        self._say_client_pairing("Select a discovered computer and enter the 6-digit code shown on its screen.", "note")
        self._refresh_discovered_devices()

    def _toggle_pairing(self) -> None:
        if self.announcer.code is not None:
            self.announcer.cancel_pairing()
            return
        if self.announcer.error:
            self._say_pairing(f"Pairing is not available: {self.announcer.error}", "note-fault")
            return
        self.announcer.begin_pairing()
        self._refresh_pairing()

    def _refresh_pairing(self) -> None:
        self._refresh_host_pairing()
        self._refresh_discovered_devices()

    def _refresh_host_pairing(self) -> None:
        code = self.announcer.code
        if code is not None:
            seconds = self.announcer.seconds_left
            self.code_label.setText(f"{code[:3]} {code[3:]}")
            widgets.set_role(self.code_label, "code")
            self.count_label.setText(f"{seconds // 60}:{seconds % 60:02d}")
            widgets.set_role(self.count_label, "count")
            self.drain.set_remaining(seconds)
            self.pair_button.setText("Cancel")
            self._say_pairing(PAIR_HINT, "note")
            self._code_shown = True
            return
        if not self._code_shown:
            return
        self._code_shown = False
        self.code_label.setText(IDLE_CODE)
        widgets.set_role(self.code_label, "code-idle")
        self.count_label.setText("1:00")
        widgets.set_role(self.count_label, "count-idle")
        self.drain.set_remaining(0)
        self.pair_button.setText("Pair a Mac")
        outcome = self.announcer.outcome
        if outcome == "refused":
            self._say_pairing("A wrong code was entered, so that code is cancelled. Press Pair a Mac for a fresh one.", "note-fault")
        elif outcome == "expired":
            self._say_pairing("The code expired. Press Pair a Mac for a fresh one.", "note-amber")
        elif outcome is None:
            self._say_pairing("Pairing cancelled.", "note")

    def _refresh_discovered_devices(self) -> None:
        if not hasattr(self, "device_combo"):
            return
        if getattr(self, "_pairing_client_active", False):
            return
        pcs = self.discovery.pcs() if hasattr(self, "discovery") and self.discovery is not None else []
        current_data = self.device_combo.currentData()
        current_addr = current_data.get("address") if isinstance(current_data, dict) else None
        key = (current_addr, tuple((pc["name"], pc["address"], pc["port"], pc.get("pair_id")) for pc in pcs))
        if key == getattr(self, "_discovered_pcs_key", None):
            return
        self._discovered_pcs_key = key

        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        if not pcs:
            self.device_combo.addItem("No devices found", None)
            if hasattr(self, "client_pair_button"):
                self.client_pair_button.setEnabled(False)
        else:
            selected_idx = 0
            for idx, pc in enumerate(pcs):
                code_tag = " (showing code)" if pc.get("pair_id") else ""
                label = f"{pc['name']} ({pc['address']}){code_tag}"
                self.device_combo.addItem(label, pc)
                if current_addr and pc["address"] == current_addr:
                    selected_idx = idx
            self.device_combo.setCurrentIndex(selected_idx)
            if hasattr(self, "client_pair_button"):
                self.client_pair_button.setEnabled(True)
        self.device_combo.blockSignals(False)

    def _start_client_pair(self) -> None:
        if getattr(self, "_pairing_client_active", False):
            return
        if not hasattr(self, "device_combo"):
            return
        pc = self.device_combo.currentData()
        if not isinstance(pc, dict):
            self._say_client_pairing("Select a discovered computer to pair with.", "note-amber")
            return
        code = self.code_entry.text().strip().replace(" ", "") if hasattr(self, "code_entry") else ""
        if len(code) != pairing.CODE_DIGITS or not code.isdigit():
            self._say_client_pairing(f"The code must be {pairing.CODE_DIGITS} digits.", "note-fault")
            return

        pcs = self.discovery.pcs() if hasattr(self, "discovery") and self.discovery is not None else []
        latest_pc = next((p for p in pcs if p["address"] == pc["address"]), pc)
        if not latest_pc.get("pair_id"):
            self._say_client_pairing(f"{latest_pc['name']} is not showing a code. Start pairing on it first.", "note-amber")
            return

        self._pairing_client_active = True
        if hasattr(self, "client_pair_button"):
            self.client_pair_button.setEnabled(False)
        self._say_client_pairing(f"Pairing with {latest_pc['name']}...", "note")

        def pair_worker():
            status_text = ""
            status_tone = "note"
            try:
                token = self.discovery.pair(latest_pc, code)
                self.bridge.client_paired.emit(token, latest_pc["name"], latest_pc["address"], latest_pc["port"])
                status_text = f"Paired with {latest_pc['name']}."
                status_tone = "note-live"
            except pairing.PairingError as exc:
                err = str(exc)
                if err == pairing.ERROR_NOT_PAIRING:
                    status_text = f"{latest_pc['name']} is no longer showing a code."
                elif err == pairing.ERROR_REFUSED:
                    status_text = "The code was refused. Check the digits and try again."
                elif err == "no_answer":
                    status_text = f"{latest_pc['name']} did not answer. Check the network connection."
                else:
                    status_text = f"Pairing failed: {err}"
                status_tone = "note-fault"
            except Exception as exc:
                LOGGER.exception("Pairing failed unexpectedly")
                status_text = f"Pairing failed: {exc}"
                status_tone = "note-fault"
            finally:
                self._pairing_client_active = False

            def finish_ui():
                if hasattr(self, "client_pair_button"):
                    self.client_pair_button.setEnabled(True)
                if status_tone == "note-live" and hasattr(self, "code_entry"):
                    self.code_entry.clear()
                self._say_client_pairing(status_text, status_tone)

            QTimer.singleShot(0, finish_ui)

        threading.Thread(target=pair_worker, name="Beamer-client-pair", daemon=True).start()

    def _say_pairing(self, text: str, tone: str) -> None:
        if hasattr(self, "pair_note"):
            if text != self.pair_note.text():
                self.pair_note.setText(text)
            widgets.set_role(self.pair_note, tone)

    def _say_client_pairing(self, text: str, tone: str = "note") -> None:
        if hasattr(self, "client_pair_note"):
            if text != self.client_pair_note.text():
                self.client_pair_note.setText(text)
            widgets.set_role(self.client_pair_note, tone)

    def _on_client_paired(self, token: str, name: str, host: str, port: int) -> None:
        current = self._config or default_config()
        try:
            candidate = replace(
                current,
                mac_host=host,
                port=port,
                auth_token=token,
                paired_with=name,
                peer_target="windows",
            )
            save_config(self.config_path, candidate)
            self._apply_config(candidate)
        except (ConfigError, TypeError, ValueError, OSError) as exc:
            LOGGER.exception("Client paired token could not be saved")
            self._say_client_pairing(f"Paired, but the configuration could not be saved: {exc}", "note-fault")
            return
        if hasattr(self, "token_entry"):
            self.token_entry.setText(token)
        if hasattr(self, "port_entry"):
            self.port_entry.setText(str(port))
        self._refresh_pairing()
        who = name or host
        self._say_client_pairing(f"Paired with {who}.", "note-live")
        LOGGER.info("Client paired with %s (%s:%d)", who, host, port)

    def _on_paired(self, token: str, mac_name: str, mac_address: str) -> None:
        current = self._config or default_config()
        host = self.host_entry.text().strip() if hasattr(self, "host_entry") else ""
        host = host or getattr(self, "_host", "") or current.host
        if not host and mac_address:
            # A fresh install knows no address of its own; the one facing the Mac is the one
            # to show.
            try:
                host = local_address_towards(mac_address)
            except OSError:
                pass
        try:
            mac_host = current.mac_host
            if mac_address and not mac_host:
                mac_host = mac_address
            port = int(self.port_entry.text().strip()) if hasattr(self, "port_entry") and self.port_entry.text().strip() else current.port
            candidate = replace(
                current,
                host=host,
                port=port,
                auth_token=token,
                paired_with=mac_name,
                mac_host=mac_host,
            )
            save_config(self.config_path, candidate)
            self._apply_config(candidate)
        except (ConfigError, TypeError, ValueError, OSError) as exc:
            LOGGER.exception("Paired token could not be saved")
            self._say_pairing(f"Paired, but the token could not be saved: {exc}", "note-fault")
            return
        self._host = candidate.host
        if hasattr(self, "host_entry"):
            self.host_entry.setText(candidate.host)
        if hasattr(self, "token_entry"):
            self.token_entry.setText(token)
        self._refresh_pairing()
        who = mac_name or "your Mac"
        self._say_pairing(f"Paired with {who}. The receiver restarted with the new token.", "note-live")
        LOGGER.info("Paired with %s", who)

    # -- Connection -------------------------------------------------------------------------

    def _connection_page(self, layout, current: Config) -> None:
        module = widgets.Module("Listening")
        fields = QGridLayout()
        fields.setHorizontalSpacing(10)
        fields.setVerticalSpacing(10)
        fields.setColumnStretch(1, 1)
        # The address the Mac connects to. Pairing fills it in; a hand set-up copies it from here.
        self.host_entry = QLineEdit(self._host)
        fields.addWidget(widgets.label("This PC's address", "key"), 0, 0)
        fields.addWidget(self.host_entry, 0, 1, 1, 2)
        self.port_entry = QLineEdit(str(current.port))
        fields.addWidget(widgets.label("Listen port", "key"), 1, 0)
        fields.addWidget(self.port_entry, 1, 1, 1, 2)
        self.token_entry = QLineEdit(current.auth_token)
        self.token_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_entry.setMinimumWidth(80)
        fields.addWidget(widgets.label("Shared token", "key"), 2, 0)
        fields.addWidget(self.token_entry, 2, 1)
        self.show_token = QPushButton("Show")
        self.show_token.setProperty("vernier", "small")
        self.show_token.setCheckable(True)
        self.show_token.setCursor(Qt.CursorShape.PointingHandCursor)
        self.show_token.setToolTip("Show the shared token in this window")
        self.show_token.toggled.connect(self._update_token_visibility)
        fields.addWidget(self.show_token, 2, 2)
        module.body.addLayout(fields)
        mac_row = QHBoxLayout()
        mac_row.setSpacing(6)
        mac_row.addWidget(widgets.label("Remote machine address (PC or Mac):", "note"))
        self.mac_host_entry = QLineEdit(current.mac_host or "")
        self.mac_host_entry.setPlaceholderText("e.g. 192.168.1.50")
        self.mac_host_readout = self.mac_host_entry
        mac_row.addWidget(self.mac_host_entry, 1)
        module.body.addLayout(mac_row)
        self.save_message = widgets.label("", "note", wrap=True)
        module.body.addWidget(self.save_message)
        self.save_button = QPushButton("Save and restart receiver")
        self.save_button.setProperty("vernier", "primary")
        self.save_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_button.clicked.connect(self.save)
        module.body.addWidget(self.save_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(module)

    def _update_token_visibility(self, checked: bool) -> None:
        self.token_entry.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
        self.show_token.setText("Hide" if checked else "Show")

    def save(self) -> None:
        current = self._config or default_config()
        try:
            candidate = replace(
                current,
                host=self.host_entry.text().strip() or self._host,
                port=int(self.port_entry.text().strip()),
                auth_token=self.token_entry.text(),
                mac_host=self.mac_host_entry.text().strip(),
            )
            save_config(self.config_path, candidate)
            self._apply_config(candidate)
        except (ConfigError, TypeError, ValueError) as exc:
            self.save_message.setText(str(exc))
            widgets.set_role(self.save_message, "note-fault")
            return
        except OSError as exc:
            LOGGER.exception("Configuration could not be saved")
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self.save_message.setText("Saved.")
        widgets.set_role(self.save_message, "note-live")

    def _apply_config(self, config: Config) -> None:
        if self.server.listening:
            self.server.stop()
        self._config = config
        if not config.edge_glow and self.glow is not None:
            self.glow.hide()
        self.allow_switch.setEnabled(True)
        self.allow_switch.setChecked(config.allow_mac_to_drive)
        if config.allow_mac_to_drive:
            self.server.start(config)
        self.send_switch.setEnabled(True)
        self.send_switch.setChecked(config.send_to_mac)
        if config.send_to_mac:
            self.sender.update_config(config)
            self._start_sending(config)
        else:
            self._stop_sending()
        self.mac_host_entry.setText(config.mac_host or "")

    # -- Firewall ---------------------------------------------------------------------------

    def _firewall_page(self, layout, current: Config) -> None:
        module = widgets.Module("Windows Firewall")
        self.firewall_note = widgets.label("Checking Windows Firewall…", "note", wrap=True)
        module.body.addWidget(self.firewall_note)
        self.firewall_button = QPushButton("Check again")
        self.firewall_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.firewall_button.setEnabled(False)
        self.firewall_button.clicked.connect(self._firewall_action)
        module.body.addWidget(self.firewall_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(module)

    def _firewall_target(self) -> tuple:
        port = self._config.port if self._config is not None else protocol.DEFAULT_PORT
        return str(Path(sys.executable).resolve()), port

    def _check_firewall(self) -> None:
        self._run_firewall(firewall_win.status, "Checking…")

    def _firewall_action(self) -> None:
        advice = self._firewall_advice
        if advice is None or advice.action is None:
            return
        if advice.action == "repair":
            profiles = advice.rule_profiles

            def job(exe, port):
                firewall_win.repair(exe, port, profiles)
                return firewall_win.status(exe, port)

        elif advice.action == "trust":
            indexes = [index for index, _ in (self._firewall_status.public_interfaces if self._firewall_status else ())]

            def job(exe, port):
                firewall_win.trust_network(indexes)
                return firewall_win.status(exe, port)

        else:
            self._check_firewall()
            return
        self._run_firewall(job, "Fixing…")

    def _run_firewall(self, job, working: str) -> None:
        """One PowerShell at a time, off the GUI thread. A request arriving mid-run is folded
        into one further status read once the current one finishes."""
        if self._closing:
            return
        if self._firewall_busy:
            self._firewall_again = True
            return
        self._firewall_busy = True
        self.firewall_button.setEnabled(False)
        self.firewall_button.setText(working)
        exe, port = self._firewall_target()

        def work():
            try:
                result = job(exe, port)
            except Exception as exc:
                LOGGER.exception("Firewall job failed")
                result = firewall_win.FirewallStatus(port, False, False, (), (), False, (), firewall_win.is_elevated(), error=f"the change failed: {exc}")
            self.bridge.firewall.emit(result)

        threading.Thread(target=work, name="Beamer-firewall", daemon=True).start()

    def _on_firewall(self, status) -> None:
        self._firewall_busy = False
        if self._closing:
            return
        self._firewall_status = status
        advice = firewall_win.advise(status)
        self._firewall_advice = advice
        self.firewall_note.setText(advice.sentence)
        if status.error:
            tone = "note-fault"
        elif advice.action == "check":
            tone = "note"
        else:
            tone = "note-amber"
        # Remembered for the sidebar dot: "check" is the healthy end-state (its button just
        # offers a manual re-check), so `advice.action is not None` alone would mark Firewall
        # as needing attention even when everything is fine.
        self._firewall_tone = tone
        widgets.set_role(self.firewall_note, tone)
        self.firewall_button.setText(advice.button)
        self.firewall_button.setEnabled(advice.action is not None)
        if self._firewall_again:
            self._firewall_again = False
            self._check_firewall()
            return
        # A missing rule with the rights to write one is not a question for the
        # user: the release installer cannot add it, so a fresh install would
        # otherwise sit unreachable until someone found this page. A block rule
        # or a public network is still theirs to decide.
        if (
            advice.action == "repair"
            and status.elevated
            and not status.allowed
            and not status.blocked
            and not self._firewall_auto_repaired
        ):
            self._firewall_auto_repaired = True
            LOGGER.info("No firewall rule for this executable; adding one")
            self._firewall_action()

    # -- theming, tray, lifecycle ------------------------------------------------------------

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.stylesheet())
        self._apply_title_bar()

    def _apply_title_bar(self) -> None:
        """Paint the native title bar in the Vernier ground instead of the user's Windows accent
        colour. Cosmetic only: any failure (older Windows without the attributes, missing dwmapi,
        etc.) is swallowed so the window still opens."""
        if sys.platform != "win32":
            return
        try:
            hwnd = int(self.winId())
        except Exception:
            LOGGER.debug("Title bar styling failed", exc_info=True)
            return
        theme.apply_titlebar(hwnd)

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(QIcon(status_icon(self._status)), self)
        self.tray.setToolTip(self._title())
        menu = QMenu()
        header = menu.addAction(f"Beamer {VERSION}")
        header.setEnabled(False)
        menu.addSeparator()
        self.open_action = menu.addAction("Open Beamer")
        self.open_action.triggered.connect(self.show_window)
        self.status_action = menu.addAction(self._title())
        self.status_action.setEnabled(False)
        self.redirect_action = menu.addAction("Send input to your Mac")
        self.redirect_action.triggered.connect(self.toggle_redirect)
        self.pause_action = menu.addAction("Pause crossing")
        self.pause_action.triggered.connect(self.toggle_pause)
        menu.addSeparator()
        # One tick per direction, each the same switch the Overview page shows, so either
        # direction can be turned off while the other keeps working and the two never disagree.
        self.drive_action = menu.addAction("Mac drives this PC")
        self.drive_action.setCheckable(True)
        self.drive_action.toggled.connect(self.allow_switch.setChecked)
        self.allow_switch.toggled.connect(self.drive_action.setChecked)
        self.send_action = menu.addAction("This PC drives the Mac")
        self.send_action.setCheckable(True)
        self.send_action.toggled.connect(self.send_switch.setChecked)
        self.send_switch.toggled.connect(self.send_action.setChecked)
        self.drive_action.setChecked(self.allow_switch.isChecked())
        self.send_action.setChecked(self.send_switch.isChecked())
        menu.addSeparator()
        menu.addAction("Reload configuration").triggered.connect(self.reload_config)
        menu.addSeparator()
        menu.addAction("About Beamer").triggered.connect(self.show_about)
        menu.addAction("Quit Beamer").triggered.connect(self.quit)
        self.tray.setContextMenu(menu)
        # Left click opens the window; right click is the
        # context menu Qt already gives QSystemTrayIcon for free.
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

    def reload_config(self) -> None:
        """Re-reads config.json, for the times it was edited outside the window, and shows it."""
        try:
            config = load_config(self.config_path)
        except (ConfigError, OSError) as exc:
            LOGGER.warning("Configuration not reloaded: %s", exc)
            self._on_alert("Beamer", f"Could not reload the configuration: {exc}")
            return
        self._host = config.host
        self._apply_config(config)
        self._configure_trigger(config)
        self._reflect_config(config)
        LOGGER.info("Configuration reloaded from %s", self.config_path)

    def _reflect_config(self, config: Config) -> None:
        """Every control on every page set from `config`, without any of them saving back."""
        for box in (*self.way_boxes.values(), self.dragging_switch, self.glow_toggle,
                    self.resistance_slider, self.double_tap_slider):
            box.blockSignals(True)
        try:
            for value, box in self.way_boxes.items():
                box.setChecked(value in config.crossing_methods)
            self.dragging_switch.setChecked(config.block_while_dragging)
            self.glow_toggle.setChecked(config.edge_glow)
            self.resistance_slider.setValue(config.crossing_resistance_px)
            self.double_tap_slider.setValue(config.double_tap_ms)
        finally:
            for box in (*self.way_boxes.values(), self.dragging_switch, self.glow_toggle,
                        self.resistance_slider, self.double_tap_slider):
                box.blockSignals(False)
        self.resistance_readout.setText(f"{config.crossing_resistance_px} px")
        self._update_resistance_hint(config.crossing_resistance_px)
        self.double_tap_readout.setText(f"{config.double_tap_ms} ms")
        self.double_tap_slider.setEnabled(config.trigger_style != "hold")
        self.corner_choice.set_value(config.crossing_corner)
        self.corner_choice.set_enabled("corner" in config.crossing_methods)
        self.edge_choice.set_value(config.mac_return_edge or "right")
        self.trigger_recorder.set_title(TRIGGER_KEYS.get(config.trigger_key, config.trigger_key))
        self.trigger_style_choice.set_value(config.trigger_style)
        self._update_style_hint(config.trigger_style)
        self.modifier_choice.set_value(config.modifier_style)
        self.modifier_note.setText(MODIFIER_NOTES[config.modifier_style])
        self.glow_style_choice.set_value(config.glow_style)
        self.glow_colour_choice.set_value(config.glow_colour)
        self._reflect_look()
        self._show_ignored(list(config.ignored_inputs))
        self.host_entry.setText(config.host)
        self.port_entry.setText(str(config.port))
        self.token_entry.setText(config.auth_token)

    def _on_tray_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.show_window()

    def start(self) -> None:
        self.announcer.start()
        if self._config is not None:
            self.server.start(self._config)
            self._start_sending(self._config)

    def _configure_trigger(self, config: Config) -> None:
        self._trigger.configure(config.trigger_key, config.trigger_style, config.double_tap_ms)

    def _start_sending(self, config: Config) -> None:
        """The outward link and the hooks that feed it. The hooks go in only
        when sending is on: they are the one part of Beamer that can take this
        PC's own keyboard away, so an install that never sends never installs
        them."""
        if not config.send_to_mac:
            return
        self._configure_trigger(config)
        try:
            self.hooks.start()
        except Exception as exc:
            LOGGER.exception("The input hooks could not be installed")
            self._sending_detail = f"This PC's keyboard could not be captured: {exc}"
            return
        self.sender.start(config)

    def _on_hook_key(self, name: str, down: bool, vk: Optional[int] = None) -> bool:
        """Every key, on the hook thread. The trigger is swallowed as it
        switches; everything else goes to the Mac only while the Mac has
        input, and a key on the ignored list not even then."""
        action = self._trigger.feed(name, down, time.monotonic())
        if action is not None:
            if not self.sender.shortcut_armed:
                # The key is still the trigger's, so it never reaches an app,
                # but with the shortcut switched off it moves nothing.
                return True
            if action == capture_win.TOGGLE:
                self.sender.toggle()
            else:
                self.sender.set_redirecting(action == capture_win.REDIRECT)
            return True
        if self._trigger.claims(name, down, self.sender.redirecting):
            return True
        return self.sender.on_key(name, down, vk)

    def _on_focus(self, target: str) -> None:
        """The Mac took input on this PC, or gave it back. Either way the
        outward edge follows: one of the two links owns the keyboard at a
        time, never both."""
        self.sender.set_receiving(target == "windows")

    def _on_learned(self, host, edge, resistance) -> None:
        """The Mac's address and the way home it named in its hello. Saved, so
        this PC can open its own link to the Mac before the Mac has crossed --
        or at all, if the Mac is asleep when Beamer starts here."""
        if self._config is None:
            return
        if sender.is_this_machine(host):
            # The Mac reached this PC through the macOS 27 localhost tunnel,
            # so its "address" is this PC's own. Saving it would point the
            # outward link at this PC's own receiver.
            LOGGER.info("Ignoring %s as the Mac's address: that is this PC", host)
            host = None
        changed = False
        if host and host != self._config.mac_host and self._config.mac_hardware_address:
            # A different Mac: the old one's hardware address would wake the wrong machine.
            self._config.mac_hardware_address = ""
            changed = True
        for name, value in (("mac_host", host), ("mac_return_edge", edge or ""), ("mac_resistance_px", resistance)):
            if value in (None, "") or getattr(self._config, name) == value:
                continue
            setattr(self._config, name, value)
            changed = True
        if not changed:
            return
        LOGGER.info("Learned the Mac at %s, coming home through the %s edge", self._config.mac_host, self._config.mac_return_edge)
        if not self._persist():
            return
        self.sender.update_config(self._config)
        self._start_sending(self._config)
        self.mac_host_entry.setText(self._config.mac_host or "")
        self.edge_choice.set_value(self._config.mac_return_edge)
        self._reflect_look()

    def _on_sending(self, connected: bool, detail: str) -> None:
        self._sending_detail = detail

    def _on_redirecting(self, redirecting: bool) -> None:
        self._sending_detail = (
            "This PC's keyboard and mouse are on the Mac" if redirecting else self.sender.status
        )

    def _announced_port(self) -> int:
        return self._config.port if self._config is not None else default_config().port

    def show_window(self) -> None:
        self.discovery.start()
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def open_home_page(self) -> None:
        QDesktopServices.openUrl(QUrl(HOME_PAGE))

    def show_about(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle("About Beamer")
        box.setIconPixmap(QIcon(str(ICON_PATH)).pixmap(64, 64))
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(
            f"<b>Beamer {VERSION}</b><br>One keyboard and mouse for your Mac and PC.<br><br>"
            f'<a href="{HOME_PAGE}" style="color: {theme.colour("signal")};">{HOME_PAGE_TEXT}</a>'
        )
        box.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        for text in box.findChildren(QLabel):
            text.setOpenExternalLinks(True)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        box.show()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._run_previews()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self.ignored_recorder.cancel()
        self.trigger_recorder.cancel()
        self._run_previews()

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            self._run_previews()

    def quit(self) -> None:
        if self._closing:
            return
        self._closing = True
        self.refresh_timer.stop()
        self.announcer.stop()
        self.discovery.stop()
        self.server.stop()
        self._stop_sending()
        if self.glow is not None:
            self.glow.hide()
        self.tray.hide()
        QApplication.quit()

    def closeEvent(self, event) -> None:
        """Closing the window hides to the tray; the tray's Quit ends the process."""
        self.discovery.stop()
        if self._closing:
            super().closeEvent(event)
            return
        event.ignore()
        self.hide()

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.hide()
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self._page == "connection":
            self.save()
            return
        super().keyPressEvent(event)

    def _stop_sending(self) -> None:
        self.sender.stop()
        self.hooks.stop()
        self._sending_detail = "Off"

    def _on_pressure(self, edge: str, pressure: float, crossed: bool) -> None:
        if self._closing or self._config is None or not self._config.edge_glow:
            return
        if self.glow is None:
            self.glow = EdgeGlow()
        self.glow.configure(self._config.glow_style, self._config.glow_colour)
        self.glow.set_pressure(edge, pressure, crossed)

    def _set_status(self, state: ServerState, detail: str) -> None:
        """Called from the receiver's thread — hand off to the GUI thread."""
        with self._status_lock:
            self._status = state
            self._status_detail = detail
        self.bridge.changed.emit(state, detail)

    def _on_status(self, state, _detail: str) -> None:
        if self._closing:
            return
        try:
            self.tray.setIcon(QIcon(status_icon(state)))
            self.tray.setToolTip(self._title())
            self.status_action.setText(self._title())
        except Exception:
            LOGGER.exception("Tray status update failed")
        # Re-read the firewall each time the receiver starts listening, never on a timer: a
        # Mac dropping and reconnecting flips WAITING <-> CONNECTED and must not trigger it.
        if state is ServerState.WAITING and self._last_seen_state not in (ServerState.WAITING, ServerState.CONNECTED):
            self._check_firewall()
        self._last_seen_state = state

    def _refresh_window(self) -> None:
        if self._closing:
            return
        with self._status_lock:
            state = self._status
            detail = self._status_detail
        tone = theme.state_tone(state.value.lower())
        self.led.set_tone(tone)
        # The Mac's name goes in the detail, not the heading: a long name wrapped the heading onto
        # two lines at 640 wide and made the window scroll.
        if state is ServerState.CONNECTED and detail.startswith("Connected to "):
            who = (self._config.paired_with if self._config is not None else "") or "Your Mac"
            detail = f"{who} at {detail[len('Connected to '):]}"
        heading = STATUS_TITLES[state]
        if heading != self.status_heading.text():
            self.status_heading.setText(heading)
        widgets.set_role(self.status_heading, HEADING_ROLE[tone])
        if detail != self.status_detail.text():
            self.status_detail.setText(detail)
        widgets.set_role(self.status_detail, "note-fault" if state is ServerState.ERROR else "note")
        location = "On your Mac" if self.sender.redirecting else "On this PC"
        if location != self.location_readout.text():
            self.location_readout.setText(location)
        trip = self.sender.round_trip_ms
        trip_text = f"{trip} ms" if trip is not None else ""
        if trip_text != self.round_trip_readout.text():
            self.round_trip_readout.setText(trip_text)
            self.round_trip_row.setVisible(trip is not None)
        redirect_text = "Bring input back to this PC" if self.sender.redirecting else "Send input to your Mac"
        if redirect_text != self.redirect_button.text():
            self.redirect_button.setText(redirect_text)
            self.redirect_action.setText(redirect_text)
        sending = self._config is not None and self._config.send_to_mac
        self.redirect_button.setEnabled(sending)
        self.redirect_action.setEnabled(sending)
        pause_text = "Resume crossing" if self.sender.crossing_paused else "Pause crossing"
        if pause_text != self.pause_button.text():
            self.pause_button.setText(pause_text)
            self.pause_action.setText(pause_text)
            widgets.set_role(self.pause_button, "primary" if self.sender.crossing_paused else "")
        sentence = self._crossing_state_sentence()
        if sentence != self.crossing_state.text():
            self.crossing_state.setText(sentence)
        # "On your Mac" above already says this while redirecting; the hint is for the rest --
        # not connected, or the hooks failing to install -- and stays quiet in the boring case.
        send_hint = "" if self.sender.redirecting or self._sending_detail in (
            "Off", "Not connected to the Mac"
        ) else self._sending_detail
        if send_hint != self.send_hint.text():
            self.send_hint.setText(send_hint)
            # Hidden while empty, or its spacing leaves a gap between the two switches.
            self.send_hint.setVisible(bool(send_hint))
        self.sidebar.set_link(tone, SIDEBAR_LINK_WORDS.get(state, "Unknown"))
        self.sidebar.set_dots(pages_win.dots(self._config is None, self._firewall_tone))
        self._refresh_pairing()
        edge = self.server.return_edge
        resistance = self.server.return_resistance
        if edge and resistance is not None:
            text = f"{edge} edge · {resistance} px"
        else:
            text = "not set yet"
        if text != self.return_readout.text():
            self.return_readout.setText(text)

    def _title(self) -> str:
        with self._status_lock:
            return f"Beamer — {self._status.value}: {self._status_detail}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Beamer Windows receiver")
    parser.add_argument("--config", type=Path, default=default_config_path(), help="path to config.json")
    parser.add_argument("--hidden", action="store_true", help="start in the tray without showing the window")
    return parser.parse_args()


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("Beamer Windows receiver must run on Windows")
    # use_last_error, then ctypes.get_last_error(): a plain GetLastError() call
    # through windll can read an error ctypes' own marshalling set in between,
    # and 183 (already exists) is the whole single-instance check.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    mutex = kernel32.CreateMutexW(None, False, "Local\\Beamer.Receiver")
    already_running = ctypes.get_last_error() == 183
    if not mutex:
        raise OSError("Beamer could not create its single-instance lock")
    if already_running:
        kernel32.CloseHandle(mutex)
        return
    arguments = parse_args()
    if arguments.config == default_config_path():
        migrate_legacy_config()
    log_path = configure_logging()
    LOGGER.info("Starting Beamer Windows receiver")
    if log_path is not None:
        LOGGER.info("Logging to %s", log_path)
    # Above normal, so a busy rig cannot starve the hooks: Windows removes a
    # low-level hook whose callback misses its timeout, silently and for good,
    # and every Beamer thread must win the CPU for the hook thread to get the
    # GIL. Beamer idles near 0%, so the class costs the rest of the machine
    # nothing (a video pipeline held half the rig on 23-09-2026 when the
    # PC's mouse was stranded on the Mac).
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    if not kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), 0x8000):  # ABOVE_NORMAL_PRIORITY_CLASS
        LOGGER.warning("Could not raise Beamer's priority: %s", ctypes.WinError(ctypes.get_last_error()))
    try:
        app = QApplication(sys.argv)
        app.setApplicationName("Beamer")
        app.setQuitOnLastWindowClosed(False)
        theme.init_fonts()
        app.setFont(theme.font(theme.TYPE["body"]))
        application = WindowsApplication(arguments.config.expanduser().resolve())
        if not arguments.hidden:
            application.show()
        application.start()
        sys.exit(app.exec())
    finally:
        kernel32.CloseHandle(mutex)


if __name__ == "__main__":
    main()
