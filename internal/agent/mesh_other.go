//go:build !windows

package agent

// meshFirewall does nothing outside Windows: the Linux agent does not manage
// the host firewall, and the documented rule (TCP and UDP on the cache port
// from the subnet) is the operator's to add.
func meshFirewall(add bool, port int) {}
