package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyExpected(t *testing.T) {
	p := Policy{
		Default: "allow",
		Rules: []Rule{
			{From: "vlan10", To: "vlan20", Action: "deny"},
			{From: "vlan30", To: "*", Action: "deny"},
			{From: "*", To: "vlan99", Action: "deny"},
			{From: "vlan40", To: "dns", Action: "deny"},
		},
	}
	cases := []struct {
		from, to, want string
	}{
		{"vlan10", "vlan20", "deny"},
		{"vlan10", "vlan30", "allow"},
		{"vlan30", "vlan10", "deny"},
		{"vlan30", "vlan20", "deny"},
		{"vlan10", "vlan99", "deny"},
		{"vlan40", "dns", "deny"},
		{"vlan50", "dns", "allow"},
		{"vlan40", "vlan50", "allow"},
	}
	for _, c := range cases {
		got, ok := p.Expected(c.from, c.to)
		if !ok {
			t.Fatalf("Expected(%s,%s): not found", c.from, c.to)
		}
		if got != c.want {
			t.Errorf("Expected(%s,%s)=%q want %q", c.from, c.to, got, c.want)
		}
	}
}

func TestPolicyNoDefault(t *testing.T) {
	p := Policy{Rules: []Rule{{From: "a", To: "b", Action: "deny"}}}
	if _, ok := p.Expected("a", "c"); ok {
		t.Fatal("expected unknown pair when no default")
	}
}

func validConfig() *Config {
	return &Config{
		Listen:   ":8080",
		Interval: Duration(30_000_000_000),
		Timeout:  Duration(1_000_000_000),
		Count:    3,
		VLANS: []VLAN{
			{Name: "vlan10", Iface: "eth1", Gateway: "192.168.10.254"},
			{Name: "vlan20", Iface: "eth2", Gateway: "192.168.20.254"},
		},
		Targets: Targets{Mode: "gateway"},
		Policy:  Policy{Default: "allow"},
	}
}

func TestValidate(t *testing.T) {
	c := validConfig()
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateRejectsBadGateway(t *testing.T) {
	c := validConfig()
	c.applyDefaults()
	c.VLANS[0].Gateway = "not-an-ip"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid gateway")
	}
}

func TestRemotes(t *testing.T) {
	c := validConfig()
	c.Remotes = []Remote{
		{Name: "internet", Targets: []string{"1.1.1.1", "8.8.8.8"}},
		{Name: "dns", Label: "DNS", Targets: []string{"192.168.1.4"}},
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid remotes rejected: %v", err)
	}
	if c.Remotes[0].Label != "internet" {
		t.Errorf("label should default to name, got %q", c.Remotes[0].Label)
	}
	if got := c.Remotes[1].DisplayName(); got != "DNS" {
		t.Errorf("DisplayName=%q", got)
	}
}

func TestRemoteNameCollidesWithVLAN(t *testing.T) {
	c := validConfig()
	c.Remotes = []Remote{{Name: "vlan10", Targets: []string{"192.168.1.4"}}}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Fatal("expected collision between remote and VLAN names")
	}
}

func TestRemoteValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		remote  Remote
		wantErr bool
	}{
		{"no target", Remote{Name: "x"}, true},
		{"bad target", Remote{Name: "x", Targets: []string{"dns.lan"}}, true},
		{"bad name", Remote{Name: "a b", Targets: []string{"1.1.1.1"}}, true},
		{"duplicate", Remote{Name: "x", Targets: []string{"1.1.1.1"}}, true},
		{"ok", Remote{Name: "ok-name", Targets: []string{"1.1.1.1"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Remotes = []Remote{tc.remote}
			if tc.name == "duplicate" {
				c.Remotes = append(c.Remotes, tc.remote)
			}
			c.applyDefaults()
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadRejectsLegacyInternet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
listen: ":8080"
vlans:
  - {name: vlan10, iface: eth1, src: 192.168.10.5/24, gateway: 192.168.10.254}
internet:
  enabled: true
  targets: ["1.1.1.1"]
policy: {default: allow}
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected legacy internet key to be rejected")
	}
	if !strings.Contains(err.Error(), "internet") {
		t.Fatalf("error should mention internet: %v", err)
	}
}

func TestLoadRejectsLegacySrc(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
listen: ":8080"
vlans:
  - {name: vlan10, iface: eth1, src: 192.168.10.5/24, gateway: 192.168.10.254}
policy: {default: allow}
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected legacy src key to be rejected")
	}
	if !strings.Contains(err.Error(), "src") {
		t.Fatalf("error should mention src: %v", err)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
listen: ":8080"
nonsense: true
vlans:
  - {name: vlan10, iface: eth1, src: 192.168.10.5/24, gateway: 192.168.10.254}
policy: {default: allow}
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
}
