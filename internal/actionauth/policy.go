package actionauth

// Class is how much authorization a request type needs. The table lives in
// the agent's code, not in anything the server sends: a signed bundle may
// raise thresholds but can never move an operation into a weaker class.
type Class int

const (
	// ClassAction is the default: unknown request types land here, so a
	// type added later is protected until someone classifies it.
	ClassAction Class = iota
	ClassRead
	ClassConfig
	ClassGrant
	ClassHighRisk
)

func (c Class) String() string {
	switch c {
	case ClassRead:
		return "read"
	case ClassConfig:
		return "config"
	case ClassGrant:
		return "grant"
	case ClassHighRisk:
		return "high-risk"
	}
	return "action"
}

var classes = map[string]Class{
	// read: no signature.
	"ping":              ClassRead,
	"inventory.refresh": ClassRead,
	"proc.list":         ClassRead,
	"svc.list":          ClassRead,
	"eventlog.query":    ClassRead,
	"updates.scan":      ClassRead,
	"script.cancel":     ClassRead,
	"wol":               ClassRead,
	"network.scan":      ClassRead,
	"snmp.poll":         ClassRead,
	// Evaluating assigned baselines only ever runs specs the agent kept,
	// and in a bundle-holding agent those are the approved ones.
	"baseline.evaluate": ClassRead,
	// These act only on a shell session, which exists only because a
	// signed shell.open created it.
	"shell.input":  ClassRead,
	"shell.resize": ClassRead,
	"shell.close":  ClassRead,

	// Staging an upload writes only into the agent's own staging area,
	// which no request can read; the bytes reach a real path only through
	// a signed fs.commit that names their size and SHA-256.
	"fs.stage": ClassRead,

	// config: intervals are unsigned; baseline specs need approvals
	// (handled by FilterBaselines, not by Check).
	"agent.config": ClassConfig,

	// grant: a short capability opens these.
	"shell.open":    ClassGrant,
	"desktop.start": ClassGrant,
	"fs.list":       ClassGrant,
	"fs.read":       ClassGrant,

	// action: one signature, one use.
	"script.run":         ClassAction,
	"proc.kill":          ClassAction,
	"svc.action":         ClassAction,
	"fs.write":           ClassAction,
	"fs.delete":          ClassAction,
	"fs.rename":          ClassAction,
	"fs.mkdir":           ClassAction,
	"fs.commit":          ClassAction,
	"power":              ClassAction,
	"updates.install":    ClassAction,
	"servicing.repair":   ClassAction,
	"baseline.remediate": ClassAction,
	"baseline.preview":   ClassAction, // runs the unsaved spec's check scripts
	"device.isolate":     ClassAction,

	// high-risk: replaces the agent's own code, or its trust.
	"agent.update": ClassHighRisk,
	"trust.update": ClassHighRisk,
}

// ClassOf returns the class of a request type. Unknown types are actions.
func ClassOf(op string) Class {
	if c, ok := classes[op]; ok {
		return c
	}
	return ClassAction
}

// Classified reports whether op has an explicit entry (used by the test that
// keeps the table in step with internal/protocol).
func Classified(op string) bool {
	_, ok := classes[op]
	return ok
}
