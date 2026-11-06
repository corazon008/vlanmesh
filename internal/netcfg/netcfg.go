package netcfg

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"vlanmesh/internal/config"
)

// Leg is one VLAN leg with its current, resolved IPv4 configuration.
type Leg struct {
	Name    string
	Iface   string
	Gateway string
	IP      net.IP
	Prefix  int
	Subnet  *net.IPNet
	Table   int
	Pref    int
}

func (l Leg) Src() string { return fmt.Sprintf("%s/%d", l.IP, l.Prefix) }

// Table returns the dedicated routing table number for VLAN index i.
func Table(i int) int { return 100 + i }

// Pref returns the ip rule preference for VLAN index i.
func Pref(i int) int { return 1000 + i }

// Resolve detects the current IPv4 address and prefix of every VLAN interface.
// The address may be DHCP-assigned and change between sweeps: nothing is taken
// from the YAML except the interface name and the gateway.
func Resolve(cfg *config.Config) ([]Leg, []string) {
	var issues []string
	legs := make([]Leg, 0, len(cfg.VLANS))
	for i, v := range cfg.VLANS {
		ifi, err := net.InterfaceByName(v.Iface)
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s: interface %s not found", v.Name, v.Iface))
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s: cannot list addresses on %s: %v", v.Name, v.Iface, err))
			continue
		}
		var chosen *net.IPNet
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || !ip4.IsGlobalUnicast() {
				continue
			}
			chosen = ipnet
			break
		}
		if chosen == nil {
			issues = append(issues, fmt.Sprintf("%s: no IPv4 address on %s yet (DHCP not ready?)", v.Name, v.Iface))
			continue
		}
		ip4 := chosen.IP.To4()
		ones, _ := chosen.Mask.Size()
		subnet := &net.IPNet{IP: ip4.Mask(chosen.Mask), Mask: chosen.Mask}
		gw := net.ParseIP(v.Gateway)
		if gw == nil {
			issues = append(issues, fmt.Sprintf("%s: invalid gateway %q", v.Name, v.Gateway))
			continue
		}
		if !subnet.Contains(gw) {
			issues = append(issues, fmt.Sprintf("%s: gateway %s is not in %s (interface %s has %s)", v.Name, v.Gateway, subnet, v.Iface, chosen.IP))
			continue
		}
		legs = append(legs, Leg{
			Name:    v.Name,
			Iface:   v.Iface,
			Gateway: v.Gateway,
			IP:      ip4,
			Prefix:  ones,
			Subnet:  subnet,
			Table:   Table(i),
			Pref:    Pref(i),
		})
	}
	return legs, issues
}

// Apply installs source-interface policy routing:
//
//	ip rule add oif <iface> lookup <table> pref <pref>
//	ip route replace <subnet> dev <iface> table <table>
//	ip route replace default via <gw> dev <iface> table <table>
//
// The rule keys on the output interface, not the source address, so a DHCP
// lease change inside the same subnet does not break it.
func Apply(legs []Leg) []string {
	var issues []string
	if _, err := exec.LookPath("ip"); err != nil {
		return append(issues, "iproute2 not found: install `ip` in the container (alpine: apk add iproute2)")
	}

	for _, leg := range legs {
		// Replace any rule at our preference, including legacy `from <IP>`
		// rules created by older versions.
		_ = run("ip", "rule", "del", "pref", itoa(leg.Pref))
		if err := run("ip", "rule", "add", "oif", leg.Iface, "lookup", itoa(leg.Table), "pref", itoa(leg.Pref)); err != nil {
			issues = append(issues, fmt.Sprintf("%s: ip rule oif %s table %d failed: %v", leg.Name, leg.Iface, leg.Table, err))
		}
		if err := run("ip", "route", "replace", leg.Subnet.String(), "dev", leg.Iface, "table", itoa(leg.Table)); err != nil {
			issues = append(issues, fmt.Sprintf("%s: route %s via %s table %d failed: %v", leg.Name, leg.Subnet, leg.Iface, leg.Table, err))
		}
		if err := run("ip", "route", "replace", "default", "via", leg.Gateway, "dev", leg.Iface, "table", itoa(leg.Table)); err != nil {
			issues = append(issues, fmt.Sprintf("%s: default via %s table %d failed: %v", leg.Name, leg.Gateway, leg.Table, err))
		}
	}

	issues = append(issues, ensureRPFilter(legs)...)
	return issues
}

// Diagnose checks the setup without changing anything.
func Diagnose(legs []Leg) []string {
	var issues []string
	if _, err := exec.LookPath("ip"); err != nil {
		return []string{"iproute2 not found"}
	}
	rules, err := output("ip", "rule", "show")
	if err != nil {
		issues = append(issues, fmt.Sprintf("cannot read ip rules: %v", err))
	}
	for _, leg := range legs {
		if !ruleExists(rules, leg) {
			issues = append(issues, fmt.Sprintf("%s: missing rule: ip rule add oif %s lookup %d pref %d", leg.Name, leg.Iface, leg.Table, leg.Pref))
		}
	}
	issues = append(issues, checkRPFilter(legs)...)
	return issues
}

func ruleExists(rules string, leg Leg) bool {
	for _, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, "oif "+leg.Iface) && strings.Contains(line, "lookup "+itoa(leg.Table)) {
			return true
		}
	}
	return false
}

// ensureRPFilter switches rp_filter to loose mode (2). Replies come back on the
// source VLAN while their reverse route belongs to another interface; strict
// mode (1) drops them.
func ensureRPFilter(legs []Leg) []string {
	var issues []string
	files := []string{
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/default/rp_filter",
	}
	for _, leg := range legs {
		files = append(files, "/proc/sys/net/ipv4/conf/"+leg.Iface+"/rp_filter")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) == "2" {
			continue
		}
		if err := os.WriteFile(f, []byte("2\n"), 0o644); err != nil {
			iface := strings.TrimSuffix(strings.TrimPrefix(f, "/proc/sys/net/ipv4/conf/"), "/rp_filter")
			issues = append(issues, fmt.Sprintf("rp_filter != 2 on %s and read-only here; on the LXC: sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.%s.rp_filter=2", iface, iface))
		}
	}
	return issues
}

func checkRPFilter(legs []Leg) []string {
	var issues []string
	files := []string{"/proc/sys/net/ipv4/conf/all/rp_filter"}
	for _, leg := range legs {
		files = append(files, "/proc/sys/net/ipv4/conf/"+leg.Iface+"/rp_filter")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) == "1" {
			iface := strings.TrimSuffix(strings.TrimPrefix(f, "/proc/sys/net/ipv4/conf/"), "/rp_filter")
			issues = append(issues, fmt.Sprintf("rp_filter=1 on %s: replies coming back on the source VLAN will be dropped; set it to 2", iface))
		}
	}
	return issues
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
