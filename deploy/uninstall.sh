#!/bin/bash
# Remove the Homelab RMM agent (default) or server (--server) from this Linux
# machine. Stops and unregisters the systemd unit, removes the binaries, and
# keeps the configuration / data unless --purge is given.
#
#   sudo bash uninstall.sh              # agent: /opt/homelab-rmm, unit HomelabRMMAgent
#   sudo bash uninstall.sh --purge      # ... and /etc/homelab-rmm (agent identity + log)
#   sudo bash uninstall.sh --server     # server: unit HomelabRMMServer; data kept
#   sudo bash uninstall.sh --server --purge --data /var/lib/homelab-rmm
#
# Afterwards, delete the device in the console (Devices -> device -> Delete)
# so it does not linger as "offline"; its record is not removed from here.
set -euo pipefail

what=agent
purge=no
data=""
usage() { sed -n '2,13p' "$0"; }
while [ $# -gt 0 ]; do
	case "$1" in
		--server) what=server ;;
		--agent) what=agent ;;
		--purge) purge=yes ;;
		--data) shift; data=${1:-} ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage; exit 2 ;;
	esac
	shift
done
if [ "$(id -u)" -ne 0 ]; then
	echo "run as root (sudo)" >&2
	exit 1
fi

# stop_unit <name>: stop, disable and remove a unit whichever way it was registered
stop_unit() {
	local unit=$1
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop "$unit" 2>/dev/null || true
		systemctl disable "$unit" 2>/dev/null || true
		rm -f "/etc/systemd/system/$unit.service"
		systemctl daemon-reload 2>/dev/null || true
		systemctl reset-failed "$unit" 2>/dev/null || true
	fi
}

# exec_path_of <unit>: the binary a unit runs, from its ExecStart line
exec_path_of() {
	local f="/etc/systemd/system/$1.service"
	[ -f "$f" ] || return 0
	sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$f" | head -n 1
}

case "$what" in
	agent)
		unit=HomelabRMMAgent
		bin=$(exec_path_of "$unit")
		[ -n "$bin" ] || bin=/opt/homelab-rmm/rmm-agent
		cfg=/etc/homelab-rmm
		if [ -x "$bin" ]; then
			# the agent knows how to unregister itself; fall through if it cannot
			"$bin" uninstall >/dev/null 2>&1 || true
		fi
		stop_unit "$unit"
		rm -f "$bin" "$bin.new" "$bin.old"
		[ -d /opt/homelab-rmm ] && rmdir /opt/homelab-rmm 2>/dev/null || true
		echo "agent service removed"
		if [ "$purge" = yes ]; then
			rm -rf "$cfg"
			echo "removed $cfg"
		else
			echo "kept $cfg (agent.json holds this device's identity AND its enrolment token, so a reinstall keeps the device's history - and a token still valid there would re-enrol it; --purge removes it)"
		fi
		;;
	server)
		unit=HomelabRMMServer
		bin=$(exec_path_of "$unit")
		if [ -z "$data" ]; then
			# the data dir is the --data flag in the unit, else the root default
			# rmm-server install writes the flags quoted ("--data" "/var/lib/x"); the
			# hand-written example unit does not. Accept both spellings.
			data=$(sed -n 's/^ExecStart=.*--data"\{0,1\}[= ]"\{0,1\}\([^" ]*\).*/\1/p' "/etc/systemd/system/$unit.service" 2>/dev/null | head -n 1)
			[ -n "$data" ] || data=/var/lib/homelab-rmm
		fi
		if [ -n "$bin" ] && [ -x "$bin" ]; then
			"$bin" uninstall >/dev/null 2>&1 || true
			rm -f "$bin"
			echo "removed $bin"
		fi
		stop_unit "$unit"
		stop_unit homelab-rmm-server   # the deploy/ example unit name
		echo "server service removed"
		if [ "$purge" = yes ]; then
			rm -rf "$data"
			echo "removed $data (database, certificate, logs)"
		else
			echo "kept $data (rmm.db, server.crt/key, server.log; --purge removes it)"
		fi
		;;
esac
