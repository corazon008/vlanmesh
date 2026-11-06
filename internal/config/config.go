package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a yaml-friendly time.Duration ("30s", "5m", "720h").
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

var remoteNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type Config struct {
	Listen      string   `yaml:"listen"`
	Interval    Duration `yaml:"interval"`
	Timeout     Duration `yaml:"timeout"`
	Count       int      `yaml:"count"`
	Concurrency int      `yaml:"concurrency"`
	DB          string   `yaml:"db"`
	Retention   Duration `yaml:"retention"`
	Demo        bool     `yaml:"demo"`
	VLANS       []VLAN   `yaml:"vlans"`
	Targets     Targets  `yaml:"targets"`
	Remotes     []Remote `yaml:"remotes"`
	Policy      Policy   `yaml:"policy"`
	Alerts      Alerts   `yaml:"alerts"`
}

type VLAN struct {
	Name    string `yaml:"name" json:"name"`
	VLANID  int    `yaml:"vlan_id" json:"vlan_id"`
	Iface   string `yaml:"iface" json:"iface"`
	Gateway string `yaml:"gateway" json:"gateway"`
}

type Targets struct {
	// Mode "gateway" probes each VLAN gateway (the firewall itself).
	// Mode "hosts" probes the host listed in Hosts[<vlan name>] (fallback: gateway).
	Mode  string            `yaml:"mode" json:"mode"`
	Hosts map[string]string `yaml:"hosts" json:"hosts"`
}

func (t Targets) For(src VLAN) string {
	if t.Mode == "hosts" {
		if h, ok := t.Hosts[src.Name]; ok && h != "" {
			return h
		}
	}
	return src.Gateway
}

// Remote is an extra destination column: a network or host outside the VLAN
// matrix (Internet, DNS server, reverse proxy, VPN subnet, remote site...).
// Reachability is tested from every VLAN.
type Remote struct {
	Name    string   `yaml:"name" json:"name"`
	Label   string   `yaml:"label" json:"label"`
	Targets []string `yaml:"targets" json:"targets"`
}

func (r Remote) DisplayName() string {
	if r.Label != "" {
		return r.Label
	}
	return r.Name
}

type Policy struct {
	Default string `yaml:"default" json:"default"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

type Rule struct {
	From   string `yaml:"from" json:"from"`
	To     string `yaml:"to" json:"to"`
	Action string `yaml:"action" json:"action"`
}

// Expected returns the intended action ("allow"/"deny") for a directed pair.
// From/To accept VLAN names and remote names. Wildcards "*" are supported.
func (p Policy) Expected(from, to string) (string, bool) {
	for _, r := range p.Rules {
		f := r.From == "*" || r.From == from
		t := r.To == "*" || r.To == to
		if f && t {
			return r.Action, true
		}
	}
	if p.Default == "allow" || p.Default == "deny" {
		return p.Default, true
	}
	return "", false
}

type Alerts struct {
	Webhook string `yaml:"webhook" json:"webhook"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if strings.Contains(err.Error(), "internet") {
			return nil, fmt.Errorf("parse %s: %w\n\n`internet:` n'existe plus : declare-le dans remotes, ex.\n  remotes:\n    - {name: internet, label: Internet, targets: [\"1.1.1.1\", \"8.8.8.8\"]}\net remplace `internet: deny` par une regle policy: {from: <vlan>, to: internet, action: deny}", path, err)
		}
		if strings.Contains(err.Error(), "src") {
			return nil, fmt.Errorf("parse %s: %w\n\n`src` n'existe plus : l'IP source est resolue depuis l'interface a chaque sweep. Supprime le champ src de chaque VLAN (garde name, iface, gateway).", path, err)
		}
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Interval == 0 {
		c.Interval = Duration(30 * time.Second)
	}
	if c.Timeout == 0 {
		c.Timeout = Duration(time.Second)
	}
	if c.Count == 0 {
		c.Count = 3
	}
	if c.Concurrency == 0 {
		c.Concurrency = 8
	}
	if c.DB == "" {
		c.DB = "/data/vlanmesh.db"
	}
	if c.Retention == 0 {
		c.Retention = Duration(720 * time.Hour)
	}
	if c.Targets.Mode == "" {
		c.Targets.Mode = "gateway"
	}
	if c.Targets.Hosts == nil {
		c.Targets.Hosts = map[string]string{}
	}
	for i := range c.Remotes {
		if c.Remotes[i].Label == "" {
			c.Remotes[i].Label = c.Remotes[i].Name
		}
	}
}

func (c *Config) Validate() error {
	if c.Interval.D() < time.Second {
		return fmt.Errorf("interval must be >= 1s")
	}
	if c.Timeout.D() <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	if c.Count < 1 || c.Count > 20 {
		return fmt.Errorf("count must be between 1 and 20")
	}
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be >= 1")
	}
	if c.Targets.Mode != "gateway" && c.Targets.Mode != "hosts" {
		return fmt.Errorf("targets.mode must be \"gateway\" or \"hosts\"")
	}
	if c.Policy.Default != "" && c.Policy.Default != "allow" && c.Policy.Default != "deny" {
		return fmt.Errorf("policy.default must be \"allow\", \"deny\" or empty")
	}
	for i, r := range c.Policy.Rules {
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("policy.rules[%d]: action must be \"allow\" or \"deny\"", i)
		}
		if r.From == "" || r.To == "" {
			return fmt.Errorf("policy.rules[%d]: from/to are required (use \"*\" for any)", i)
		}
	}
	if len(c.VLANS) == 0 {
		return fmt.Errorf("vlans: at least one VLAN is required")
	}
	seen := map[string]bool{}
	for i := range c.VLANS {
		v := &c.VLANS[i]
		if v.Name == "" {
			return fmt.Errorf("vlans[%d]: name is required", i)
		}
		if seen[v.Name] {
			return fmt.Errorf("vlans[%d]: duplicate name %q", i, v.Name)
		}
		seen[v.Name] = true
		if v.Iface == "" {
			return fmt.Errorf("vlans[%d] (%s): iface is required", i, v.Name)
		}
		if v.Gateway == "" {
			return fmt.Errorf("vlans[%d] (%s): gateway is required", i, v.Name)
		}
		gw := net.ParseIP(v.Gateway)
		if gw == nil {
			return fmt.Errorf("vlans[%d] (%s): invalid gateway %q", i, v.Name, v.Gateway)
		}
	}

	remoteNames := map[string]bool{}
	for i := range c.Remotes {
		r := &c.Remotes[i]
		if r.Name == "" {
			return fmt.Errorf("remotes[%d]: name is required", i)
		}
		if !remoteNameRe.MatchString(r.Name) {
			return fmt.Errorf("remotes[%d] (%s): name must match [a-zA-Z0-9_-]+", i, r.Name)
		}
		if remoteNames[r.Name] {
			return fmt.Errorf("remotes[%d]: duplicate name %q", i, r.Name)
		}
		remoteNames[r.Name] = true
		if seen[r.Name] {
			return fmt.Errorf("remotes[%d] (%s): name collides with a VLAN name", i, r.Name)
		}
		if len(r.Targets) == 0 {
			return fmt.Errorf("remotes[%d] (%s): at least one target is required", i, r.Name)
		}
		for j, t := range r.Targets {
			if net.ParseIP(t) == nil {
				return fmt.Errorf("remotes[%d] (%s): invalid target[%d] %q (IPv4/IPv6 literal expected)", i, r.Name, j, t)
			}
		}
	}
	return nil
}
