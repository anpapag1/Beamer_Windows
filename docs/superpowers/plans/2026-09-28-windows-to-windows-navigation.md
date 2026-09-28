# Windows-to-Windows Native Mouse & Keyboard Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable native Windows-to-Windows mouse and keyboard navigation in Beamer, resolving the one-sided Mac-to-Windows assumptions across pairing, wire protocol focus state, modifier keys, and UI configuration.

**Architecture:** 
1. Generalize target negotiation in `sender.py` and `receiver.py` so focus transitions and return edges operate symmetrically between two Windows machines.
2. Enable direct IP entry on Windows Connection page and symmetric peer pairing via `pairing.Discovery` in `win_app/kvm_bridge_win.py`.
3. Provide native 1:1 modifier key mapping in `capture_win.py` for Windows peers (avoiding the Mac Ctrl ⇄ Cmd semantic swap).
4. Maintain byte-for-byte parity for shared modules between `win_app` and `mac_app`.

**Tech Stack:** Python 3.14, PySide6 (Qt 6), Win32 API (`ctypes.windll.user32`), pytest.

**Spec / Requirements:**
- Must allow two Windows PCs running `win_app` to pair and navigate across screen boundaries seamlessly.
- Must preserve full backward compatibility with Mac ⇄ Windows operation.
- Must preserve byte-for-byte parity for shared modules verified by `test_shared_copies.py`.
- Must support 1:1 Windows modifier shortcuts (Ctrl stays Ctrl, Win stays Win) when navigating Windows-to-Windows.

---

### Task 1: Protocol Target Symmetry & Switch Handling

**Files:**
- Modify: `win_app/sender.py`
- Modify: `win_app/receiver.py`
- Modify: `mac_app/receiver.py` (to maintain byte-for-byte parity)
- Test: `win_app/tests/test_sender.py`
- Test: `win_app/tests/test_receiver.py`
- Test: `win_app/tests/test_shared_copies.py`

**Interfaces:**
- `receiver.ReceiverServer`: accepts incoming focus and switch messages, correctly identifying whether input is arriving or departing regardless of peer OS.
- `sender.MacSender` (generalizable to `PeerSender`): sends recipient-compatible focus targets and accepts switch back requests from a Windows peer.

- [ ] **Step 1: Write failing test in `test_sender.py` for Windows-to-Windows focus and switch handling**

```python
def test_switch_from_windows_peer_triggers_switch_back(self):
    # Verify sender accepts switch_msg target from another Windows receiver
    sender = MacSender(redirect_callback=lambda val: None)
    sender.redirecting = True
    # Windows receiver sends switch_msg with peer_target ("mac" or "peer" or "windows")
    sender._handle_switch({"target": "mac"})
    self.assertFalse(sender.redirecting)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest win_app/tests/test_sender.py -k test_switch_from_windows_peer_triggers_switch_back`
Expected: FAIL (currently drops target != "windows").

- [ ] **Step 3: Update `win_app/sender.py` and `win_app/receiver.py`**

In `win_app/sender.py`:
- In `_handle_switch`: accept switch messages targeting `"windows"`, `"mac"`, or `"peer"`.
- In `set_redirecting`: allow target parameterization so that when connecting to a Windows receiver, it sends `target="windows"` on outbound redirect and `target="mac"` on return (matching receiver's expected `self_target` and `peer_target`).

In `win_app/receiver.py`:
- Keep `self_target="windows"` and `peer_target="mac"`.
- Copy updated `win_app/receiver.py` to `mac_app/receiver.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest win_app/tests/test_sender.py win_app/tests/test_receiver.py win_app/tests/test_shared_copies.py`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add win_app/sender.py win_app/receiver.py mac_app/receiver.py win_app/tests/test_sender.py
git commit -m "fix(protocol): support symmetric focus and switch handling for Windows peers"
```

---

### Task 2: 1:1 Modifier Key Mapping for Windows-to-Windows

**Files:**
- Modify: `win_app/capture_win.py`
- Modify: `win_app/sender.py`
- Test: `win_app/tests/test_capture_win.py`
- Test: `win_app/tests/test_sender.py`

**Interfaces:**
- `capture_win.Hooks` / `sender.MacSender`: when `peer_os == "windows"`, map Ctrl to `"ctrl"` and Win to `"cmd"` so that `input_injector.py` injects real Ctrl (`0xA2`) and real Win (`0x5B`) on the receiving Windows PC.

- [ ] **Step 1: Write failing test in `test_capture_win.py`**

```python
def test_windows_peer_modifier_mapping_preserves_ctrl_and_win(self):
    # For Windows peers, Ctrl should map to "ctrl" wire name, not "cmd"
    wire_name = sender._wire_name_for_peer("ctrl", peer_is_windows=True)
    self.assertEqual(wire_name, "ctrl")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest win_app/tests/test_capture_win.py -k test_windows_peer_modifier_mapping`
Expected: FAIL.

- [ ] **Step 3: Implement peer OS modifier translation in `win_app/sender.py`**

In `win_app/sender.py`:
- In `_wire_name`: when communicating with a Windows peer, map `"cmd"` (captured from Ctrl) back to `"ctrl"`, and `"ctrl"` (captured from Win key) back to `"cmd"` (or identity mapping), ensuring Ctrl+C injects as Ctrl+C on the peer.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest win_app/tests/test_capture_win.py win_app/tests/test_sender.py`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add win_app/sender.py win_app/tests/test_capture_win.py win_app/tests/test_sender.py
git commit -m "feat(keyboard): add 1:1 modifier mapping for Windows peers"
```

---

### Task 3: Configurable Peer Address in Windows UI

**Files:**
- Modify: `win_app/app_config.py`
- Modify: `win_app/kvm_bridge_win.py`
- Test: `win_app/tests/test_app_config.py`

**Interfaces:**
- `app_config.Config`: `mac_host` field accessible as remote peer address.
- `kvm_bridge_win.MainWindow._connection_page`: editable `QLineEdit` for remote peer IP address, allowing manual Windows-to-Windows setup without relying on incoming packets.

- [ ] **Step 1: Write test for saving and loading peer address**

```python
def test_peer_host_entry_persists(self):
    cfg = load_config(path)
    self.assertEqual(cfg.mac_host, "192.168.1.100")
```

- [ ] **Step 2: Run test to verify existing behavior**

Run: `pytest win_app/tests/test_app_config.py`
Expected: PASS.

- [ ] **Step 3: Update `win_app/kvm_bridge_win.py`**

- In `_connection_page`: replace `self.mac_host_readout = widgets.label(...)` with:
  ```python
  self.mac_host_entry = QLineEdit(current.mac_host)
  ```
  with label `"Remote PC / Mac address:"`.
- In `save()`: read `self.mac_host_entry.text().strip()` and include in `candidate` config.
- In `_apply_config`: trigger `self.sender.update_config(config)` and start outbound sender if peer address is set.

- [ ] **Step 4: Verify tests pass**

Run: `pytest win_app/tests/test_app_config.py`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add win_app/kvm_bridge_win.py win_app/tests/test_app_config.py
git commit -m "feat(ui): make remote peer address editable on Windows Connection page"
```

---

### Task 4: Windows Pairing Discovery & Client UI

**Files:**
- Modify: `win_app/kvm_bridge_win.py`
- Test: `win_app/tests/test_pairing.py`

**Interfaces:**
- `kvm_bridge_win.MainWindow`: instantiates `pairing.Discovery` on startup alongside `Announcer`.
- `_pairing_page`: renders discovered machines on LAN and allows entering the 6-digit pairing code to pair directly with another PC.

- [ ] **Step 1: Add unit tests verifying `Discovery` starts in Windows bridge**

- [ ] **Step 2: Implement `Discovery` integration and peer list in `win_app/kvm_bridge_win.py`**
  - Initialize `self.discovery = pairing.Discovery(logger=LOGGER)`.
  - Start `self.discovery.start()` in `__init__` and stop in `closeEvent`.
  - Add peer selection and code confirmation dialog/module in `_pairing_page`.
  - Upon pairing success, store peer host, port, and auth token and apply config.

- [ ] **Step 3: Run all pairing and win_app tests**

Run: `pytest win_app/tests/test_pairing.py win_app/tests/test_pages_win.py`
Expected: PASS.

- [ ] **Step 4: Commit changes**

```bash
git add win_app/kvm_bridge_win.py win_app/tests/test_pairing.py
git commit -m "feat(pairing): enable LAN discovery and pairing client on Windows"
```

---

### Task 5: End-to-End Test Suite & Verification

**Files:**
- Create: `win_app/tests/test_win_to_win.py`
- Run: Entire `win_app/tests` suite

- [ ] **Step 1: Write comprehensive test simulating two Windows instances exchanging mouse and keyboard**
- [ ] **Step 2: Run all tests in repository**
  `$env:PYTHONPATH="win_app"; pytest win_app/tests`
- [ ] **Step 3: Verify byte parity with `mac_app`**
  `pytest win_app/tests/test_shared_copies.py`
- [ ] **Step 4: Commit end-to-end tests**
