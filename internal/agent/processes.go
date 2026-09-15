package agent

import (
	"errors"
	"sort"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func listProcesses() ([]protocol.Process, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}
	out := make([]protocol.Process, 0, len(procs))
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		pp := protocol.Process{PID: p.Pid, Name: name}
		if ppid, err := p.Ppid(); err == nil {
			pp.PPID = ppid
		}
		if u, err := p.Username(); err == nil {
			pp.User = u
		}
		if c, err := p.CPUPercent(); err == nil {
			pp.CPUPct = round1(c)
		}
		if mi, err := p.MemoryInfo(); err == nil && mi != nil {
			pp.MemRSS = mi.RSS
		}
		if cl, err := p.Cmdline(); err == nil {
			if len(cl) > 512 {
				cl = cl[:512] + "..."
			}
			pp.Cmdline = cl
		}
		if ct, err := p.CreateTime(); err == nil {
			pp.Started = ct / 1000
		}
		out = append(out, pp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MemRSS > out[j].MemRSS })
	return out, nil
}

func killProcess(pid int32) error {
	if pid <= 4 {
		return errors.New("refusing to kill a system process")
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
