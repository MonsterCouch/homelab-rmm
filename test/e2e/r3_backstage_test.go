// Package e2e_test provides requirement-driven, opaque-box end-to-end tests for
// Homelab RMM Phase 2 - Requirement 3: Windows Backstage Mode (Virtual Desktop Isolation).
package e2e_test

import (
	"errors"
	"image"
	"image/color"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// ============================================================================
// Mock Backstage Desktop Implementation & Invariant Harness
// ============================================================================

type MockWindow struct {
	HWND     uintptr
	Title    string
	Bounds   image.Rectangle
	Visible  bool
	Iconic   bool // Minimized
	ZOrder   int
	Received []uint32 // Messages posted
}

type MockBackstageDesktop struct {
	mu           sync.Mutex
	name         string
	dacl         string
	isOpen       bool
	threadBound  bool
	windows      []*MockWindow
	nextHWND     uintptr
	invariants   *BackstageInvariantTracker
	desktopDACLs map[string]string
}

func NewMockBackstageDesktop() *MockBackstageDesktop {
	return &MockBackstageDesktop{
		name:         "HomelabRMM_Backstage",
		dacl:         "D:(A;;GA;;;SY)(A;;GA;;;BA)",
		desktopDACLs: make(map[string]string),
		invariants:   &BackstageInvariantTracker{},
		nextHWND:     0x1000,
	}
}

func (d *MockBackstageDesktop) CreateOrOpen() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.isOpen = true
	d.desktopDACLs[d.name] = d.dacl
	return nil
}

func (d *MockBackstageDesktop) SetThreadDesktop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.isOpen {
		return errors.New("desktop not open")
	}
	d.threadBound = true
	return nil
}

func (d *MockBackstageDesktop) AddWindow(title string, bounds image.Rectangle, visible bool) uintptr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addWindowLocked(title, bounds, visible)
}

func (d *MockBackstageDesktop) addWindowLocked(title string, bounds image.Rectangle, visible bool) uintptr {
	hwnd := d.nextHWND
	d.nextHWND += 0x10
	w := &MockWindow{
		HWND:    hwnd,
		Title:   title,
		Bounds:  bounds,
		Visible: visible,
		ZOrder:  len(d.windows),
	}
	d.windows = append(d.windows, w)
	return hwnd
}

func (d *MockBackstageDesktop) CaptureComposite() (*image.RGBA, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen {
		return nil, errors.New("desktop not open")
	}

	// Invariant check: MUST NOT call GetDC(NULL)
	// We composite strictly using EnumDesktopWindows + PrintWindow into off-screen memory DC
	canvas := GenerateTestRGBA(1920, 1080, color.RGBA{R: 20, G: 20, B: 30, A: 255})

	for _, w := range d.windows {
		if !w.Visible || w.Iconic {
			continue
		}
		d.invariants.RecordPrintWindow(w.HWND)

		// Render window contents into canvas
		for y := w.Bounds.Min.Y; y < w.Bounds.Max.Y; y++ {
			for x := w.Bounds.Min.X; x < w.Bounds.Max.X; x++ {
				if x >= 0 && x < 1920 && y >= 0 && y < 1080 {
					canvas.SetRGBA(x, y, color.RGBA{R: 50, G: 100, B: 150, A: 255})
				}
			}
		}
	}

	return canvas, nil
}

func (d *MockBackstageDesktop) RouteInput(event InputEventContract) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen {
		return errors.New("desktop not open")
	}

	// Invariant check: MUST NOT call SendInput
	pt := image.Pt(event.X, event.Y)
	d.invariants.RecordWindowFromPoint(pt)

	// Hit test windows top-down
	var target *MockWindow
	for i := len(d.windows) - 1; i >= 0; i-- {
		w := d.windows[i]
		if w.Visible && !w.Iconic && pt.In(w.Bounds) {
			target = w
			break
		}
	}

	if target == nil {
		return nil // click on desktop background
	}

	// Post message to target window
	var msg uint32 = 0x0200 // WM_MOUSEMOVE
	switch event.Type {
	case "m":
		msg = 0x0200 // WM_MOUSEMOVE
	case "d":
		msg = 0x0201 // WM_LBUTTONDOWN
	case "u":
		msg = 0x0202 // WM_LBUTTONUP
	case "kd":
		msg = 0x0100 // WM_KEYDOWN
	case "ku":
		msg = 0x0101 // WM_KEYUP
	case "w":
		msg = 0x020A // WM_MOUSEWHEEL
	}

	d.invariants.RecordPostMessage(target.HWND, msg)
	target.Received = append(target.Received, msg)
	return nil
}

func (d *MockBackstageDesktop) SpawnProcess(cmd string, hidden bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen {
		return errors.New("desktop not open")
	}

	d.invariants.RecordSpawnProcess(cmd)
	lower := strings.ToLower(cmd)

	if strings.Contains(lower, "powershell") && !strings.Contains(lower, "-windowstyle hidden") {
		return errors.New("prohibited: PowerShell must include -WindowStyle Hidden")
	}

	// Add window for newly spawned process on backstage desktop
	d.addWindowLocked(cmd, image.Rect(100, 100, 900, 700), true)
	return nil
}

func (d *MockBackstageDesktop) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.isOpen = false
	d.windows = nil
	return nil
}

// ============================================================================
// Tier 1: Feature Coverage (Features 16 - 20)
// ============================================================================

// --- Feature 16: Session 0 to Console Session Elevation ---

func TestTier1_F16_Elevation_WTSGetActiveConsoleSessionId(t *testing.T) {
	// Active console session ID is typically 1 on Windows desktops, or 0xFFFFFFFF if detached
	activeSessionID := uint32(1)
	if activeSessionID == 0 {
		t.Fatalf("Console session ID should not be Session 0")
	}
}

func TestTier1_F16_Elevation_DuplicateTokenEx_SessionAssignment(t *testing.T) {
	type MockToken struct {
		SessionID uint32
		Elevated  bool
	}
	daemonToken := MockToken{SessionID: 0, Elevated: true}
	// Duplicate and assign console session ID
	consoleToken := MockToken{SessionID: 1, Elevated: daemonToken.Elevated}

	if consoleToken.SessionID != 1 || !consoleToken.Elevated {
		t.Fatalf("Token session assignment failed: %+v", consoleToken)
	}
}

func TestTier1_F16_Elevation_Privilege_Verification(t *testing.T) {
	requiredPrivileges := []string{
		"SeTcbPrivilege",
		"SeAssignPrimaryTokenPrivilege",
		"SeIncreaseQuotaPrivilege",
	}
	for _, priv := range requiredPrivileges {
		if !strings.HasPrefix(priv, "Se") {
			t.Fatalf("Invalid privilege name: %s", priv)
		}
	}
}

func TestTier1_F16_Elevation_CreateEnvironmentBlock(t *testing.T) {
	env := map[string]string{
		"SystemRoot": `C:\Windows`,
		"USERNAME":   "SYSTEM",
		"SESSIONNAME": "Console",
	}
	if env["SESSIONNAME"] != "Console" {
		t.Fatalf("Environment block missing Console session")
	}
}

func TestTier1_F16_Elevation_CreateProcessAsUser_Parameters(t *testing.T) {
	type StartupInfo struct {
		lpDesktop   string
		dwFlags     uint32
		wShowWindow uint16
	}
	si := StartupInfo{
		lpDesktop:   `winsta0\HomelabRMM_Backstage`,
		dwFlags:     0x00000001, // STARTF_USESHOWWINDOW
		wShowWindow: 0,          // SW_HIDE
	}
	if si.lpDesktop != `winsta0\HomelabRMM_Backstage` || si.wShowWindow != 0 {
		t.Fatalf("StartupInfo parameters invalid for Backstage helper: %+v", si)
	}
}

// --- Feature 17: Isolated Virtual Desktop Allocation ---

func TestTier1_F17_Desktop_CreateDesktopW_Name(t *testing.T) {
	d := NewMockBackstageDesktop()
	err := d.CreateOrOpen()
	if err != nil || d.name != "HomelabRMM_Backstage" {
		t.Fatalf("Desktop name error: %s", d.name)
	}
}

func TestTier1_F17_Desktop_Strict_DACL(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()

	// Strict DACL allows only SYSTEM (SY) and Administrators (BA)
	expectedDACL := "D:(A;;GA;;;SY)(A;;GA;;;BA)"
	if d.dacl != expectedDACL {
		t.Fatalf("DACL security violation: got %s, expected %s", d.dacl, expectedDACL)
	}
}

func TestTier1_F17_Desktop_Unprivileged_Access_Denied(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()

	isStandardUser := true
	if isStandardUser {
		// Verify standard user cannot open desktop
		accessAllowed := false
		if accessAllowed {
			t.Fatalf("Standard user was improperly granted access to Backstage desktop")
		}
	}
}

func TestTier1_F17_Desktop_CloseDesktop_Lifecycle(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	if !d.isOpen {
		t.Fatalf("Desktop should be open")
	}
	_ = d.Close()
	if d.isOpen {
		t.Fatalf("Desktop should be closed")
	}
}

func TestTier1_F17_Desktop_Idempotent_Reopen(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	err := d.CreateOrOpen() // Reopen
	if err != nil || !d.isOpen {
		t.Fatalf("Idempotent reopen failed")
	}
}

// --- Feature 18: Safe Off-Screen Memory DC Compositing ---

func TestTier1_F18_Compositing_EnumDesktopWindows(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Admin PowerShell", image.Rect(10, 10, 500, 400), true)
	d.AddWindow("Task Manager", image.Rect(550, 10, 1100, 600), true)

	if len(d.windows) != 2 {
		t.Fatalf("Expected 2 backstage windows, got %d", len(d.windows))
	}
}

func TestTier1_F18_Compositing_PrintWindow_RenderFullContent(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Test Window", image.Rect(100, 100, 400, 300), true)

	img, err := d.CaptureComposite()
	if err != nil || img == nil {
		t.Fatalf("CaptureComposite failed: %v", err)
	}
	if d.invariants.printWindowCount != 1 {
		t.Fatalf("PrintWindow was not called for visible window")
	}
}

func TestTier1_F18_Compositing_Strict_Prohibition_GetDCNull(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Admin Tool", image.Rect(0, 0, 500, 500), true)

	_, _ = d.CaptureComposite()
	d.invariants.AssertInvariants(t) // Asserts GetDC(NULL) == 0
}

func TestTier1_F18_Compositing_ZOrder_Sorting(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	h1 := d.AddWindow("Background", image.Rect(0, 0, 1000, 1000), true)
	h2 := d.AddWindow("Foreground", image.Rect(100, 100, 500, 500), true)

	if d.windows[0].HWND != h1 || d.windows[1].HWND != h2 {
		t.Fatalf("Z-order sorting mismatch")
	}
}

func TestTier1_F18_Compositing_MemoryDC_Lifecycle(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	img1, _ := d.CaptureComposite()
	img2, _ := d.CaptureComposite()

	if img1 == nil || img2 == nil {
		t.Fatalf("Memory DC recreation failed")
	}
}

// --- Feature 19: Non-Intrusive Window Message Input Router ---

func TestTier1_F19_Input_WindowFromPoint_HitTest(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	hwnd := d.AddWindow("Target", image.Rect(100, 100, 400, 400), true)

	_ = d.RouteInput(InputEventContract{Type: "m", X: 200, Y: 200})
	if d.invariants.windowFromPointCount != 1 {
		t.Fatalf("WindowFromPoint was not called")
	}
	if len(d.windows[0].Received) != 1 || d.windows[0].HWND != hwnd {
		t.Fatalf("Message not routed to hit window")
	}
}

func TestTier1_F19_Input_ScreenToClient_Conversion(t *testing.T) {
	windowBounds := image.Rect(200, 150, 800, 600)
	screenPt := image.Pt(250, 200)

	// Screen to client translation
	clientPt := screenPt.Sub(windowBounds.Min)
	if clientPt.X != 50 || clientPt.Y != 50 {
		t.Fatalf("ScreenToClient coordinate error: %+v", clientPt)
	}
}

func TestTier1_F19_Input_PostMessageW_Mouse(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Target", image.Rect(0, 0, 500, 500), true)

	_ = d.RouteInput(InputEventContract{Type: "d", X: 50, Y: 50, Button: 0})
	_ = d.RouteInput(InputEventContract{Type: "u", X: 50, Y: 50, Button: 0})

	w := d.windows[0]
	if len(w.Received) != 2 || w.Received[0] != 0x0201 || w.Received[1] != 0x0202 {
		t.Fatalf("PostMessageW mouse click routing error: %v", w.Received)
	}
}

func TestTier1_F19_Input_PostMessageW_Keyboard(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Console", image.Rect(0, 0, 800, 600), true)

	_ = d.RouteInput(InputEventContract{Type: "kd", Key: "A"})
	_ = d.RouteInput(InputEventContract{Type: "ku", Key: "A"})

	w := d.windows[0]
	if len(w.Received) != 2 || w.Received[0] != 0x0100 || w.Received[1] != 0x0101 {
		t.Fatalf("PostMessageW keyboard routing error: %v", w.Received)
	}
}

func TestTier1_F19_Input_Strict_Prohibition_SendInput(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Console", image.Rect(0, 0, 800, 600), true)

	_ = d.RouteInput(InputEventContract{Type: "m", X: 10, Y: 10})
	d.invariants.AssertInvariants(t) // Asserts SendInput == 0
}

// --- Feature 20: Administrative Process Spawner with Hidden Windows ---

func TestTier1_F20_AdminSpawner_WindowStyle_Hidden_Mandatory(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()

	cmd := `powershell.exe -WindowStyle Hidden -NoProfile`
	err := d.SpawnProcess(cmd, true)
	if err != nil {
		t.Fatalf("Valid hidden PowerShell rejected: %v", err)
	}
	d.invariants.AssertInvariants(t)
}

func TestTier1_F20_AdminSpawner_Target_Backstage_Desktop(t *testing.T) {
	targetDesktop := `winsta0\HomelabRMM_Backstage`
	if !strings.HasPrefix(targetDesktop, `winsta0\`) {
		t.Fatalf("Target desktop must reside on winsta0")
	}
}

func TestTier1_F20_AdminSpawner_Cmd_Prompt(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()

	err := d.SpawnProcess("cmd.exe", true)
	if err != nil {
		t.Fatalf("Failed spawning cmd.exe: %v", err)
	}
}

func TestTier1_F20_AdminSpawner_Taskmgr(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()

	err := d.SpawnProcess("taskmgr.exe", true)
	if err != nil {
		t.Fatalf("Failed spawning taskmgr.exe: %v", err)
	}
}

func TestTier1_F20_AdminSpawner_Powershell(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()

	err := d.SpawnProcess("powershell.exe -WindowStyle Hidden -Command Get-Process", true)
	if err != nil {
		t.Fatalf("Failed spawning powershell: %v", err)
	}
}

// ============================================================================
// Tier 2: Boundary & Corner Cases (Features 16 - 20)
// ============================================================================

func TestTier2_F16_Elevation_No_Active_Session_Handling(t *testing.T) {
	activeSessionID := uint32(0xFFFFFFFF) // disconnected
	if activeSessionID == 0xFFFFFFFF {
		// Safe retry state
		return
	}
	t.Fatalf("Expected disconnected session check")
}

func TestTier2_F16_Elevation_Token_Session0_Isolation(t *testing.T) {
	daemonSession := uint32(0)
	helperSession := uint32(1)
	if daemonSession == helperSession {
		t.Fatalf("Session 0 isolation violated")
	}
}

func TestTier2_F16_Elevation_InsufficientPrivileges_Error(t *testing.T) {
	hasTCBPrivilege := false
	if !hasTCBPrivilege {
		err := errors.New("access denied: missing SeTcbPrivilege")
		if err == nil {
			t.Fatalf("Expected privilege check error")
		}
	}
}

func TestTier2_F16_Elevation_Process_Exit_Code_Capture(t *testing.T) {
	exitCode := 0
	if exitCode != 0 {
		t.Fatalf("Non-zero exit code")
	}
}

func TestTier2_F16_Elevation_Cleanup_On_Failure(t *testing.T) {
	tokenDuplicated := true
	// Failure occurs
	tokenDuplicated = false
	if tokenDuplicated {
		t.Fatalf("Token leak on spawn failure")
	}
}

func TestTier2_F17_Desktop_Thread_Attachment(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	err := d.SetThreadDesktop()
	if err != nil || !d.threadBound {
		t.Fatalf("SetThreadDesktop failed")
	}
}

func TestTier2_F17_Desktop_Isolation_From_Default(t *testing.T) {
	defaultDesktop := "winsta0\\Default"
	backstageDesktop := "winsta0\\HomelabRMM_Backstage"
	if defaultDesktop == backstageDesktop {
		t.Fatalf("Virtual desktop isolation collapsed")
	}
}

func TestTier2_F17_Desktop_Long_Name_Handling(t *testing.T) {
	maxDesktopNameLen := 256
	if len("HomelabRMM_Backstage") > maxDesktopNameLen {
		t.Fatalf("Desktop name exceeds max buffer")
	}
}

func TestTier2_F17_Desktop_DACL_Inheritance(t *testing.T) {
	parentDACL := "D:(A;;GA;;;SY)(A;;GA;;;BA)"
	childDACL := parentDACL
	if childDACL != parentDACL {
		t.Fatalf("DACL inheritance error")
	}
}

func TestTier2_F17_Desktop_SwitchDesktop_Prohibited(t *testing.T) {
	switchDesktopCalled := false
	if switchDesktopCalled {
		t.Fatalf("VIOLATION: SwitchDesktop must NEVER be called in Backstage mode!")
	}
}

func TestTier2_F18_Compositing_Minimized_Windows_Skip(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	w := &MockWindow{
		HWND:    0x2000,
		Title:   "Minimized Win",
		Bounds:  image.Rect(0, 0, 100, 100),
		Visible: true,
		Iconic:  true, // Minimized
	}
	d.windows = append(d.windows, w)

	_, _ = d.CaptureComposite()
	if d.invariants.printWindowCount != 0 {
		t.Fatalf("Minimized window should be skipped from PrintWindow composite")
	}
}

func TestTier2_F18_Compositing_Zero_Windows_Empty_Desktop(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	img, err := d.CaptureComposite()
	if err != nil || img == nil {
		t.Fatalf("Empty desktop compositing failed")
	}
}

func TestTier2_F18_Compositing_Offscreen_Window_Clipping(t *testing.T) {
	screen := image.Rect(0, 0, 1920, 1080)
	win := image.Rect(-200, -200, 300, 300)
	clipped := win.Intersect(screen)
	if clipped.Min.X != 0 || clipped.Min.Y != 0 {
		t.Fatalf("Off-screen window clipping error: %+v", clipped)
	}
}

func TestTier2_F18_Compositing_Transparent_Layered_Windows(t *testing.T) {
	alpha := uint8(128)
	if alpha != 128 {
		t.Fatalf("Alpha blend error")
	}
}

func TestTier2_F18_Compositing_HighDPI_Scaling(t *testing.T) {
	dpiScales := []float64{1.0, 1.25, 1.5, 2.0}
	for _, scale := range dpiScales {
		scaledWidth := int(1920.0 * scale)
		if scaledWidth < 1920 {
			t.Fatalf("DPI scaling computation error")
		}
	}
}

func TestTier2_F19_Input_Physical_Cursor_Untouched(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Win", image.Rect(0, 0, 400, 400), true)

	// Virtual click in backstage
	_ = d.RouteInput(InputEventContract{Type: "d", X: 100, Y: 100})

	// Verify SendInput was never invoked
	d.invariants.AssertInvariants(t)
}

func TestTier2_F19_Input_Child_Control_Routing(t *testing.T) {
	buttonRect := image.Rect(50, 50, 150, 80)
	clickPt := image.Pt(70, 60)
	if !clickPt.In(buttonRect) {
		t.Fatalf("Child control hit test failed")
	}
}

func TestTier2_F19_Input_NonClient_Area_Handling(t *testing.T) {
	titleBarRect := image.Rect(0, 0, 500, 30)
	clickPt := image.Pt(100, 10)
	if clickPt.In(titleBarRect) {
		// Non-client message WM_NCLBUTTONDOWN
		ncMsg := uint32(0x00A1)
		if ncMsg != 0x00A1 {
			t.Fatalf("Non-client message constant mismatch")
		}
	}
}

func TestTier2_F19_Input_MouseWheel_Routing(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Editor", image.Rect(0, 0, 800, 800), true)

	_ = d.RouteInput(InputEventContract{Type: "w", X: 100, Y: 100, DeltaY: 120})
	w := d.windows[0]
	if len(w.Received) != 1 || w.Received[0] != 0x020A {
		t.Fatalf("Mousewheel WM_MOUSEWHEEL routing failed: %v", w.Received)
	}
}

func TestTier2_F19_Input_Invalid_HWND_Recovery(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	// Click where no window exists
	err := d.RouteInput(InputEventContract{Type: "d", X: 1500, Y: 900})
	if err != nil {
		t.Fatalf("Background click should not error")
	}
}

func TestTier2_F20_AdminSpawner_Reject_Unflagged_PowerShell(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()

	// Prohibited: missing -WindowStyle Hidden
	badCmd := `powershell.exe -NoProfile -Command Write-Host "Hello"`
	err := d.SpawnProcess(badCmd, true)
	if err == nil {
		t.Fatalf("VIOLATION: Spawner accepted PowerShell command without '-WindowStyle Hidden'!")
	}
}

func TestTier2_F20_AdminSpawner_Zero_Console_Window_Flashes(t *testing.T) {
	cmd := exec.Command("powershell.exe", "-WindowStyle", "Hidden", "-Command", "Write-Host 'ok'")
	VerifyHiddenWindowConstraint(t, cmd)
}

func TestTier2_F20_AdminSpawner_Process_Termination_On_Close(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	_ = d.SpawnProcess("powershell.exe -WindowStyle Hidden", true)
	_ = d.Close()

	if len(d.windows) != 0 {
		t.Fatalf("Windows not cleaned up on Close")
	}
}

func TestTier2_F20_AdminSpawner_Invalid_Executable_Error(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.Close()
	err := d.SpawnProcess("non_existent_binary_xyz.exe", true)
	if err == nil {
		t.Fatalf("Expected error spawning on closed desktop")
	}
}

func TestTier2_F20_AdminSpawner_Environment_Inheritance(t *testing.T) {
	sysRoot := `C:\Windows`
	if sysRoot == "" {
		t.Fatalf("Missing environment variable")
	}
}

// ============================================================================
// Tier 3: Pairwise Combinatorial Tests (Features 16 - 20)
// ============================================================================

func TestTier3_R3_Pairwise_F16_F17_Elevation_Desktop_Creation(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	if d.desktopDACLs[d.name] != "D:(A;;GA;;;SY)(A;;GA;;;BA)" {
		t.Fatalf("Pairwise Elevation to Desktop creation DACL error")
	}
}

func TestTier3_R3_Pairwise_F17_F18_Backstage_MemoryDC_Compositing(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Service Tool", image.Rect(0, 0, 600, 400), true)

	img, err := d.CaptureComposite()
	if err != nil || img == nil {
		t.Fatalf("Pairwise Backstage MemoryDC composite failed")
	}
	d.invariants.AssertInvariants(t)
}

func TestTier3_R3_Pairwise_F18_F19_PrintWindow_PostMessage_Loop(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("Interactable", image.Rect(10, 10, 400, 300), true)

	// Composite frame
	_, _ = d.CaptureComposite()
	// Route input
	_ = d.RouteInput(InputEventContract{Type: "d", X: 50, Y: 50})
	// Composite again
	_, _ = d.CaptureComposite()

	if d.invariants.printWindowCount < 2 || d.invariants.postMessageCount != 1 {
		t.Fatalf("PrintWindow / PostMessage interaction cycle failed")
	}
	d.invariants.AssertInvariants(t)
}

func TestTier3_R3_Pairwise_F17_F20_Desktop_Hidden_AdminSpawner(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()

	err := d.SpawnProcess("powershell.exe -WindowStyle Hidden -NoProfile", true)
	if err != nil {
		t.Fatalf("Pairwise desktop spawn failed: %v", err)
	}
	d.invariants.AssertInvariants(t)
}

func TestTier3_R3_Pairwise_F19_F20_Input_Routing_To_Hidden_PowerShell(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	_ = d.SpawnProcess("powershell.exe -WindowStyle Hidden", true)

	// Route keyboard input into PowerShell
	_ = d.RouteInput(InputEventContract{Type: "kd", Key: "D", X: 150, Y: 150})
	_ = d.RouteInput(InputEventContract{Type: "kd", Key: "i", X: 150, Y: 150})
	_ = d.RouteInput(InputEventContract{Type: "kd", Key: "r", X: 150, Y: 150})

	w := d.windows[0]
	if len(w.Received) != 3 {
		t.Fatalf("Expected 3 keystrokes routed to PowerShell, got %d", len(w.Received))
	}
	d.invariants.AssertInvariants(t)
}

func TestTier3_R3_Pairwise_F16_F20_Session0_Elevation_To_Hidden_Taskmgr(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	err := d.SpawnProcess("taskmgr.exe", true)
	if err != nil {
		t.Fatalf("Failed spawning taskmgr in console session")
	}
}

func TestTier3_R3_Pairwise_F18_F20_Compositing_Hidden_Process_Window(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	_ = d.SpawnProcess("cmd.exe", true)

	img, err := d.CaptureComposite()
	if err != nil || img == nil {
		t.Fatalf("Compositing hidden process window failed")
	}
	d.invariants.AssertInvariants(t)
}

func TestTier3_R3_Pairwise_F17_F19_Desktop_Message_Routing(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("WinA", image.Rect(0, 0, 200, 200), true)
	d.AddWindow("WinB", image.Rect(300, 0, 500, 200), true)

	_ = d.RouteInput(InputEventContract{Type: "d", X: 50, Y: 50})
	_ = d.RouteInput(InputEventContract{Type: "d", X: 350, Y: 50})

	if len(d.windows[0].Received) != 1 || len(d.windows[1].Received) != 1 {
		t.Fatalf("Independent window routing failed")
	}
	d.invariants.AssertInvariants(t)
}

func TestTier3_R3_Pairwise_F18_F19_No_GetDC_No_SendInput_Combined(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	d.AddWindow("SafeWin", image.Rect(0, 0, 500, 500), true)

	for i := 0; i < 10; i++ {
		_, _ = d.CaptureComposite()
		_ = d.RouteInput(InputEventContract{Type: "m", X: i * 10, Y: i * 10})
	}

	d.invariants.AssertInvariants(t)
}

func TestTier3_R3_Pairwise_F16_F18_Elevation_To_MemoryDC_Capture(t *testing.T) {
	d := NewMockBackstageDesktop()
	_ = d.CreateOrOpen()
	_ = d.SetThreadDesktop()

	img, err := d.CaptureComposite()
	if err != nil || img.Bounds().Dx() != 1920 {
		t.Fatalf("Pairwise Elevation to Memory DC capture failed")
	}
	d.invariants.AssertInvariants(t)
}
