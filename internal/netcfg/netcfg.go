package netcfg

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"vlanmesh/internal/config"
)

// Apply sets up source-based policy routing so a probe sourced from VLAN i
// physically leaves through eth_i (and therefore hits the firewall), instead
// of taking the directly connected route of the destination VLAN.
//
// It is idempotent and best-effort: problems are returned as human readable
// issues so the UI can display them.
func Apply(cfg *config.Config) []string {
	var issues []string

	if _, err := exec.LookPath("ip"); err != nil {
		return append(issues, "iproute2 not found: install `ip` in the container (alpine: apk add iproute2)")
	}

	for i, v := range cfg.VLANS {
		table := Table(i)
		pref := Pref(i)
		srcIP := v.SrcIP()
		subnet := v.Subnet()
		if srcIP == "" || subnet == "" {
			issues = append(issues, fmt.Sprintf("%s: invalid src %q", v.Name, v.Src))
			continue
		}

		if err := run("ip", "link", "show", "dev", v.Iface); err != nil {
			issues = append(issues, fmt.Sprintf("%s: interface %s not found (check Proxmox net%d)", v.Name, v.Iface, i+1))
			continue
		}

		addrOut, err := output("ip", "-4", "-o", "addr", "show", "dev", v.Iface)
		if err != nil || !strings.Contains(addrOut, srcIP+"/") {
			issues = append(issues, fmt.Sprintf("%s: %s is not configured on %s (expected %s)", v.Name, srcIP, v.Iface, v.Src))
		}

		// Connected route inside the per-VLAN table.
		if err := run("ip", "route", "replace", subnet, "dev", v.Iface, "src", srcIP, "table", itoa(table)); err != nil {
			issues = append(issues, fmt.Sprintf("%s: route %s via %s table %d failed: %v", v.Name, subnet, v.Iface, table, err))
		}
		// Default route inside the per-VLAN table -> firewall.
		if err := run("ip", "route", "replace", "default", "via", v.Gateway, "dev", v.Iface, "table", itoa(table)); err != nil {
			issues = append(issues, fmt.Sprintf("%s: default via %s table %d failed: %v", v.Name, v.Gateway, table, err))
		}
		// Policy rule: traffic sourced from this VLAN's IP uses its own table.
		if ok, _ := hasRule(srcIP, table); !ok {
			if err := run("ip", "rule", "add", "from", srcIP, "lookup", itoa(table), "pref", itoa(pref)); err != nil {
				if !strings.Contains(err.Error(), "File exists") {
					issues = append(issues, fmt.Sprintf("%s: ip rule from %s table %d failed: %v", v.Name, srcIP, table, err))
				}
			}
		}

		// Strict rp_filter drops replies coming back on the source VLAN
		// (their reverse route lives on another VLAN). Loose mode (2) is required.
		if v2, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + v.Iface + "/rp_filter"); err == nil {
			if strings.TrimSpace(string(v2)) == "1" {
				if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+v.Iface+"/rp_filter", []byte("2\n"), 0o644); err != nil {
					issues = append(issues, fmt.Sprintf("%s: rp_filter=1 on %s and cannot be changed from the container; run on the LXC: sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.%s.rp_filter=2", v.Name, v.Iface, v.Iface))
				}
			}
		}
	}

	if v, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter"); err == nil {
		if strings.TrimSpace(string(v)) == "1" {
			if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("2\n"), 0o644); err != nil {
				issues = append(issues, "net.ipv4.conf.all.rp_filter=1 and read-only here; run on the LXC: sysctl -w net.ipv4.conf.all.rp_filter=2")
			}
		}
	}

	return issues
}

// Diagnose checks the network setup without changing anything.
func Diagnose(cfg *config.Config) []string {
	var issues []string
	if _, err := exec.LookPath("ip"); err != nil {
		return append(issues, "iproute2 not found")
	}
	for i, v := range cfg.VLANS {
		srcIP := v.SrcIP()
		if err := run("ip", "link", "show", "dev", v.Iface); err != nil {
			issues = append(issues, fmt.Sprintf("%s: interface %s not found", v.Name, v.Iface))
			continue
		}
		out, err := output("ip", "-4", "-o", "addr", "show", "dev", v.Iface)
		if err != nil || !strings.Contains(out, srcIP+"/") {
			issues = append(issues, fmt.Sprintf("%s: %s not configured on %s", v.Name, srcIP, v.Iface))
		}
		ok, err := hasRule(srcIP, Table(i))
		if err != nil || !ok {
			issues = append(issues, fmt.Sprintf("%s: missing policy rule: ip rule add from %s lookup %d pref %d", v.Name, srcIP, Table(i), Pref(i)))
		}
	}
	for _, f := range []string{"all"} {
		if b, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + f + "/rp_filter"); err == nil {
			if strings.TrimSpace(string(b)) == "1" {
				issues = append(issues, "rp_filter=1: replies coming back on the source VLAN will be dropped; set net.ipv4.conf.all.rp_filter=2")
			}
		}
	}
	return issues
}

// Table returns the dedicated routing table number for VLAN index i.
func Table(i int) int { return 100 + i }

// Pref returns the ip rule preference for VLAN index i.
func Pref(i int) int { return 1000 + i }

func hasRule(srcIP string, table int) (bool, error) {
	out, err := output("ip", "rule", "show")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "from "+srcIP+" ") && strings.Contains(line, "lookup "+itoa(table)) {
			return true, nil
		}
	}
	return false, nil
}

// Commands returns the routing commands that Apply runs, for docs/debug.
func Commands(cfg *config.Config) []string {
	var cmds []string
	for i, v := range cfg.VLANS {
		cmds = append(cmds,
			fmt.Sprintf("ip route replace %s dev %s src %s table %d", v.Subnet(), v.Iface, v.SrcIP(), Table(i)),
			fmt.Sprintf("ip route replace default via %s dev %s table %d", v.Gateway, v.Iface, Table(i)),
			fmt.Sprintf("ip rule add from %s lookup %d pref %d", v.SrcIP(), Table(i), Pref(i)),
		)
	}
	return cmds
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s: %s", err, msg)
		}
		return err
	}
	return nil
}

func output(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
