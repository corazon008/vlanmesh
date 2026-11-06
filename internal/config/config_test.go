package config

import "testing"

func TestPolicyExpected(t *testing.T) {
	p := Policy{
		Default: "allow",
		Rules: []Rule{
			{From: "vlan10", To: "vlan20", Action: "deny"},
			{From: "vlan30", To: "*", Action: "deny"},
			{From: "*", To: "vlan99", Action: "deny"},
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
			{Name: "vlan10", Iface: "eth1", Src: "192.168.10.5/24", Gateway: "192.168.10.254"},
			{Name: "vlan20", Iface: "eth2", Src: "192.168.20.5/24", Gateway: "192.168.20.254"},
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

func TestValidateRejectsBadCIDR(t *testing.T) {
	c := validConfig()
	c.applyDefaults()
	c.VLANS[0].Src = "192.168.10.5"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing prefix")
	}
}

func TestValidateRejectsOverlapGateway(t *testing.T) {
	c := validConfig()
	c.applyDefaults()
	c.VLANS[0].Gateway = "192.168.20.254"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for gateway outside subnet")
	}
}

func TestVLANHelpers(t *testing.T) {
	v := VLAN{Src: "192.168.10.5/24"}
	if got := v.SrcIP(); got != "192.168.10.5" {
		t.Errorf("SrcIP=%q", got)
	}
	if got := v.Subnet(); got != "192.168.10.0/24" {
		t.Errorf("Subnet=%q", got)
	}
}
