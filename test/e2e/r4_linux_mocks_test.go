// Mock Linux input, portal and session-detection types shared by the
// Windows-hosted r4 tests and by phase2_scenarios_test.go. They use only the
// standard library, so they build on every platform; the tests that exercise
// them stay in r4_linux_windows_test.go (Windows) and r4_linux_test.go (Linux),
// which declare the same test names and therefore cannot both build at once.
package e2e_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
)

// Linux input_event struct (64-bit architecture)
type WinLinuxInputEvent struct {
	Sec   int64
	Usec  int64
	Type  uint16
	Code  uint16
	Value int32
}

func (e *WinLinuxInputEvent) Marshal() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, e.Sec)
	_ = binary.Write(buf, binary.LittleEndian, e.Usec)
	_ = binary.Write(buf, binary.LittleEndian, e.Type)
	_ = binary.Write(buf, binary.LittleEndian, e.Code)
	_ = binary.Write(buf, binary.LittleEndian, e.Value)
	return buf.Bytes()
}

func UnmarshalWinLinuxInputEvent(data []byte) (*WinLinuxInputEvent, error) {
	if len(data) < 24 {
		return nil, errors.New("data too short for 64-bit input_event")
	}
	r := bytes.NewReader(data)
	e := &WinLinuxInputEvent{}
	_ = binary.Read(r, binary.LittleEndian, &e.Sec)
	_ = binary.Read(r, binary.LittleEndian, &e.Usec)
	_ = binary.Read(r, binary.LittleEndian, &e.Type)
	_ = binary.Read(r, binary.LittleEndian, &e.Code)
	_ = binary.Read(r, binary.LittleEndian, &e.Value)
	return e, nil
}

const (
	WinLinuxEV_SYN = 0x00
	WinLinuxEV_KEY = 0x01
	WinLinuxEV_REL = 0x02
	WinLinuxEV_ABS = 0x03

	WinLinuxREL_X     = 0x00
	WinLinuxREL_Y     = 0x01
	WinLinuxREL_WHEEL = 0x08

	WinLinuxBTN_LEFT   = 0x110
	WinLinuxBTN_RIGHT  = 0x111
	WinLinuxBTN_MIDDLE = 0x112

	WinLinuxKEY_A     = 30
	WinLinuxKEY_ENTER = 28
	WinLinuxKEY_ESC   = 1
)

type WinMockPortalScreenCastSession struct {
	mu           sync.Mutex
	sessionPath  string
	persistMode  uint32
	restoreToken string
	pipewireNode uint32
	cursorMode   uint32
	sourceType   uint32
	userAccepted bool
	closed       bool
}

func NewWinMockPortalScreenCastSession() *WinMockPortalScreenCastSession {
	return &WinMockPortalScreenCastSession{
		sessionPath:  "/org/freedesktop/portal/desktop/session/123",
		pipewireNode: 42,
		userAccepted: true,
	}
}

func (p *WinMockPortalScreenCastSession) SelectSources(options map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if pm, ok := options["persist_mode"]; ok {
		if val, ok := pm.(uint32); ok {
			p.persistMode = val
		}
	}
	if tok, ok := options["restore_token"]; ok {
		if val, ok := tok.(string); ok {
			p.restoreToken = val
		}
	}
	if cm, ok := options["cursor_mode"]; ok {
		if val, ok := cm.(uint32); ok {
			p.cursorMode = val
		}
	}
	if st, ok := options["source_type"]; ok {
		if val, ok := st.(uint32); ok {
			p.sourceType = val
		}
	}
	return nil
}

func (p *WinMockPortalScreenCastSession) Start() (nodeID uint32, token string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.userAccepted {
		return 0, "", errors.New("user cancelled portal request")
	}

	if p.persistMode == 2 && p.restoreToken == "" {
		p.restoreToken = "rt_tok_unattended_789abc"
	}

	return p.pipewireNode, p.restoreToken, nil
}

type WinMockUInputDevice struct {
	mu       sync.Mutex
	events   []WinLinuxInputEvent
	isOpen   bool
	devType  string
	hasPerms bool
}

func NewWinMockUInputDevice(devType string, hasPerms bool) *WinMockUInputDevice {
	return &WinMockUInputDevice{
		devType:  devType,
		hasPerms: hasPerms,
		isOpen:   hasPerms,
	}
}

func (u *WinMockUInputDevice) Emit(evt WinLinuxInputEvent) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.hasPerms {
		return errors.New("permission denied: /dev/uinput (EACCES)")
	}
	if !u.isOpen {
		return errors.New("uinput device closed")
	}

	u.events = append(u.events, evt)
	return nil
}

func (u *WinMockUInputDevice) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.isOpen = false
	return nil
}

type WinLinuxSessionDetector struct {
	xdgSessionType string
	waylandDisplay string
	display        string
	loginctlType   string
	pipewireActive bool
}

func (s *WinLinuxSessionDetector) Detect() (string, error) {
	if s.waylandDisplay != "" || s.xdgSessionType == "wayland" || s.loginctlType == "wayland" {
		if !s.pipewireActive {
			return "wayland", errors.New("wayland session detected but PipeWire daemon is not running")
		}
		return "wayland", nil
	}

	if s.display != "" || s.xdgSessionType == "x11" || s.loginctlType == "x11" {
		return "x11", nil
	}

	return "unknown", errors.New("headless linux: no graphical display server detected")
}
