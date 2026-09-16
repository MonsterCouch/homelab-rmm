//go:build windows

package agent

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestListServicesKeepsAReadableStartType is F073 on a real SCM: a service
// may only be reported with start type "unknown" when its configuration is
// genuinely unreadable. Reading the configuration all-or-nothing used to
// break that invariant for every service whose description is an "@dll,-N"
// MUI reference the system can no longer resolve - three of them on a stock
// Windows 11, including WaaSMedicSvc, which is exactly the service an
// operator audits.
func TestListServicesKeepsAReadableStartType(t *testing.T) {
	svcs, err := listServices()
	if err != nil {
		t.Skipf("cannot list services here: %v", err)
	}
	if len(svcs) == 0 {
		t.Skip("no services on this device")
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		t.Skipf("cannot open the SCM here: %v", err)
	}
	defer windows.CloseServiceHandle(scm)
	var lost []string
	for _, s := range svcs {
		if s.StartType != "unknown" {
			continue
		}
		ms, err := openService(scm, s.Name, windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			continue // no rights, or it went away between the two calls
		}
		_, cerr := serviceConfig(ms.Handle)
		ms.Close()
		if cerr == nil {
			lost = append(lost, s.Name)
		}
	}
	if len(lost) > 0 {
		t.Errorf("start type reported as unknown although the configuration is readable: %v", lost)
	}
}
