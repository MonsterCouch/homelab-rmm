//go:build windows

package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// svcActionTimeout bounds the wait for a state change after start/stop.
// The SCM's own default is 30 s; a service that takes longer is a finding
// the operator should see, not something to wait out silently.
const svcActionTimeout = 30 * time.Second

var errServiceNotFound = errors.New("service does not exist")

// svcStatus is one row of EnumServicesStatusEx.
type svcStatus struct {
	name, display string
	state, pid    uint32
}

// enumServices lists every Win32 service with its status in one SCM call.
// Opening each service to query its status would need a handle per
// service and fails on the few whose DACL excludes even SYSTEM.
func enumServices(scm windows.Handle) ([]svcStatus, error) {
	var (
		buf                      []byte
		needed, returned, resume uint32
	)
	for attempt := 0; ; attempt++ {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			p, uint32(len(buf)), &needed, &returned, &resume, nil)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("EnumServicesStatusEx: %w", err)
		}
		if attempt >= 5 {
			return nil, errors.New("EnumServicesStatusEx: buffer never large enough")
		}
		// needed is what is still missing after a partial fill; start over
		// with room for everything rather than stitching partial pages.
		buf = make([]byte, len(buf)+int(needed)+4096)
		resume, returned = 0, 0
	}
	if returned == 0 {
		return nil, nil
	}
	entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), returned)
	out := make([]svcStatus, 0, returned)
	for _, e := range entries {
		out = append(out, svcStatus{
			name:    windows.UTF16PtrToString(e.ServiceName),
			display: windows.UTF16PtrToString(e.DisplayName),
			state:   e.ServiceStatusProcess.CurrentState,
			pid:     e.ServiceStatusProcess.ProcessId,
		})
	}
	return out, nil
}

// openService opens one service with exactly the rights the caller needs;
// mgr.OpenService asks for SERVICE_ALL_ACCESS, which protected services
// (Defender, Sense) refuse even to SYSTEM.
func openService(scm windows.Handle, name string, access uint32) (*mgr.Service, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("service name %q: %w", name, err)
	}
	h, err := windows.OpenService(scm, n, access)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, fmt.Errorf("%q: %w", name, errServiceNotFound)
		}
		return nil, fmt.Errorf("open service %q: %w", name, err)
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

// describeService reads status and configuration into a wire Service. The
// config half needs SERVICE_QUERY_CONFIG; when the handle lacks it the
// start type is reported as unknown rather than failing the row.
func describeService(s *mgr.Service, display string) protocol.Service {
	out := protocol.Service{Name: s.Name, DisplayName: display, State: "unknown", StartType: "unknown"}
	if st, err := s.Query(); err == nil {
		out.State = winServiceStateName(uint32(st.State))
		out.PID = int(st.ProcessId)
	}
	if cfg, err := s.Config(); err == nil {
		out.StartType = winServiceStartTypeName(cfg.StartType, cfg.DelayedAutoStart)
		out.Description = winCleanServiceDescription(cfg.Description)
		if out.DisplayName == "" {
			out.DisplayName = cfg.DisplayName
		}
	}
	if out.DisplayName == "" {
		out.DisplayName = s.Name
	}
	return out
}

// listServices returns every Win32 service sorted by display name.
func listServices() ([]protocol.Service, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("open service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	statuses, err := enumServices(scm)
	if err != nil {
		return nil, err
	}
	out := make([]protocol.Service, 0, len(statuses))
	for _, st := range statuses {
		s := protocol.Service{Name: st.name, DisplayName: st.display, State: winServiceStateName(st.state), StartType: "unknown", PID: int(st.pid)}
		if s.DisplayName == "" {
			s.DisplayName = st.name
		}
		if ms, err := openService(scm, st.name, windows.SERVICE_QUERY_CONFIG); err == nil {
			if cfg, err := ms.Config(); err == nil {
				s.StartType = winServiceStartTypeName(cfg.StartType, cfg.DelayedAutoStart)
				s.Description = winCleanServiceDescription(cfg.Description)
			}
			ms.Close()
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].DisplayName) < strings.ToLower(out[j].DisplayName)
	})
	return out, nil
}

// serviceAccessFor maps an action to the least service rights it needs.
func serviceAccessFor(action string) (uint32, bool) {
	const base = uint32(windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG)
	switch action {
	case "start":
		return base | windows.SERVICE_START, true
	case "stop":
		return base | windows.SERVICE_STOP | windows.SERVICE_ENUMERATE_DEPENDENTS, true
	case "restart":
		return base | windows.SERVICE_START | windows.SERVICE_STOP | windows.SERVICE_ENUMERATE_DEPENDENTS, true
	case "enable", "disable", "manual":
		return base | windows.SERVICE_CHANGE_CONFIG, true
	}
	return 0, false
}

// serviceAction performs start|stop|restart|enable|disable|manual and
// returns the service as it is afterwards.
func serviceAction(name, action string) (*protocol.Service, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 256 || strings.ContainsAny(name, `/\`) {
		return nil, errors.New("invalid service name")
	}
	action = strings.ToLower(strings.TrimSpace(action))
	access, ok := serviceAccessFor(action)
	if !ok {
		return nil, fmt.Errorf("unknown service action %q", action)
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, fmt.Errorf("open service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	s, err := openService(scm, name, access)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	deadline := time.Now().Add(svcActionTimeout)
	switch action {
	case "start":
		err = startService(s, deadline)
	case "stop":
		err = stopService(scm, s, deadline, 0, nil)
	case "restart":
		// The SCM makes a stop take the running dependents down too; a
		// restart that left them stopped would be a silent outage.
		var stopped []string
		if err = stopService(scm, s, deadline, 0, &stopped); err == nil {
			if err = startService(s, time.Now().Add(svcActionTimeout)); err == nil {
				restartDependents(scm, stopped)
			}
		}
	case "enable":
		err = setStartType(s, windows.SERVICE_AUTO_START)
	case "disable":
		err = setStartType(s, windows.SERVICE_DISABLED)
	case "manual":
		err = setStartType(s, windows.SERVICE_DEMAND_START)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", action, name, err)
	}
	out := describeService(s, "")
	return &out, nil
}

func startService(s *mgr.Service, deadline time.Time) error {
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		if errors.Is(err, windows.ERROR_SERVICE_DISABLED) {
			return errors.New("the service is disabled; set it to manual or automatic first")
		}
		return fmt.Errorf("start: %w", err)
	}
	return waitForState(s, svc.Running, deadline)
}

// stopService stops s after its active dependents, which the SCM insists
// on (ERROR_DEPENDENT_SERVICES_RUNNING otherwise). depth guards against a
// pathological dependency graph. When stopped is non-nil every dependent
// that was actually stopped is appended to it, deepest first, so a restart
// can bring them back in reverse order.
func stopService(scm windows.Handle, s *mgr.Service, deadline time.Time, depth int, stopped *[]string) error {
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query status: %w", err)
	}
	if st.State == svc.Stopped {
		return nil
	}
	if depth > 8 {
		return errors.New("dependency chain too deep")
	}
	if deps, err := s.ListDependentServices(svc.Active); err == nil {
		for _, d := range deps {
			ds, err := openService(scm, d, windows.SERVICE_QUERY_STATUS|windows.SERVICE_STOP|windows.SERVICE_ENUMERATE_DEPENDENTS)
			if err != nil {
				return fmt.Errorf("dependent service: %w", err)
			}
			err = stopService(scm, ds, deadline, depth+1, stopped)
			ds.Close()
			if err != nil {
				return fmt.Errorf("stop dependent %s: %w", d, err)
			}
			if stopped != nil {
				*stopped = append(*stopped, d)
			}
		}
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			switch {
			case errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
				return nil
			case errors.Is(err, windows.ERROR_INVALID_SERVICE_CONTROL):
				return errors.New("the service does not accept stop requests")
			}
			return fmt.Errorf("stop: %w", err)
		}
	}
	return waitForState(s, svc.Stopped, deadline)
}

// restartDependents brings back the dependents a restart had to stop, in
// reverse stop order so each one's own dependencies are up before it. A
// dependent that will not start is logged, not fatal: the service the
// operator asked about did restart, and the reply describes that one.
func restartDependents(scm windows.Handle, stopped []string) {
	for i := len(stopped) - 1; i >= 0; i-- {
		name := stopped[i]
		ds, err := openService(scm, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_START)
		if err != nil {
			slog.Warn("restart: cannot reopen dependent service", "service", name, "err", err)
			continue
		}
		if err := startService(ds, time.Now().Add(svcActionTimeout)); err != nil {
			slog.Warn("restart: dependent service did not come back", "service", name, "err", err)
		}
		ds.Close()
	}
}

// waitForState polls until the service reaches want or deadline passes. A
// service asked to run that lands back in Stopped has died on startup; a
// non-zero exit code says so at once, a zero one after a short grace
// period (the first poll can still see the pre-start Stopped).
func waitForState(s *mgr.Service, want svc.State, deadline time.Time) error {
	var stoppedSince time.Time
	for {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query status: %w", err)
		}
		if st.State == want {
			return nil
		}
		if want == svc.Running && st.State == svc.Stopped {
			if st.Win32ExitCode != 0 || st.ServiceSpecificExitCode != 0 {
				return fmt.Errorf("the service stopped right after starting (exit code %d, service-specific %d)", st.Win32ExitCode, st.ServiceSpecificExitCode)
			}
			if stoppedSince.IsZero() {
				stoppedSince = time.Now()
			} else if time.Since(stoppedSince) > 3*time.Second {
				return errors.New("the service exited right after starting")
			}
		} else {
			stoppedSince = time.Time{}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s (state is %s)", svcActionTimeout, winServiceStateName(uint32(want)), winServiceStateName(uint32(st.State)))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// setStartType changes only the start type. Everything else is passed as
// SERVICE_NO_CHANGE / NULL so the binary path, account and dependencies are
// left exactly as they were; the delayed-auto-start flag is likewise left
// alone so re-enabling a delayed service restores it as delayed.
func setStartType(s *mgr.Service, startType uint32) error {
	err := windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, startType, windows.SERVICE_NO_CHANGE,
		nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("change start type: %w", err)
	}
	return nil
}

// serviceState is the cheap per-sample probe for monitored services.
func serviceState(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "unknown"
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseServiceHandle(scm)
	s, err := openService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, errServiceNotFound) {
			return "not_found"
		}
		return "unknown"
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "unknown"
	}
	return winServiceStateName(uint32(st.State))
}
