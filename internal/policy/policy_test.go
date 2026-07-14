// Tests for the policy engine. Policy is the difference between "a
// signing oracle" and "a CA": these tests pin deny-by-default, subset
// checks, TTL caps, wildcard semantics, and the strict parsing that
// keeps a typoed field from silently widening access.
package policy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// testPolicy builds a representative document exercising defaults,
// inheritance, wildcard, and per-user overrides.
func testPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse([]byte(`{
		"version": 1,
		"defaults": {"max_ttl": "8h", "extensions": ["permit-pty"]},
		"users": {
			"alice":  {"principals": ["alice", "deploy"], "max_ttl": "1h"},
			"ci-bot": {"principals": ["deploy"], "max_ttl": "15m", "extensions": [],
			           "source_address": ["10.0.0.0/8"], "force_command": "/usr/local/bin/deploy"},
			"root-op": {"principals": ["*"]}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUnknownUserIsDenied(t *testing.T) {
	p := testPolicy(t)
	_, err := p.Authorize("mallory", []string{"deploy"}, time.Minute)
	var deny *DenyError
	if !errors.As(err, &deny) {
		t.Fatalf("err = %v, want *DenyError", err)
	}
	if deny.User != "mallory" {
		t.Fatalf("deny names %q", deny.User)
	}
}

func TestAllowedPrincipalSubset(t *testing.T) {
	p := testPolicy(t)
	g, err := p.Authorize("alice", []string{"deploy"}, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Principals) != 1 || g.Principals[0] != "deploy" {
		t.Fatalf("principals = %v", g.Principals)
	}
	if g.TTL != 30*time.Minute {
		t.Fatalf("ttl = %v", g.TTL)
	}
}

func TestDisallowedPrincipalIsDenied(t *testing.T) {
	p := testPolicy(t)
	_, err := p.Authorize("alice", []string{"deploy", "root"}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), `"root"`) {
		t.Fatalf("err = %v, want denial naming root", err)
	}
}

func TestEmptyRequestGrantsAllNamedPrincipalsSorted(t *testing.T) {
	p := testPolicy(t)
	g, err := p.Authorize("alice", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Principals) != 2 || g.Principals[0] != "alice" || g.Principals[1] != "deploy" {
		t.Fatalf("principals = %v, want sorted [alice deploy]", g.Principals)
	}
}

func TestTTLCapEnforcement(t *testing.T) {
	p := testPolicy(t)
	// Zero requests the full cap.
	g, err := p.Authorize("alice", []string{"alice"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if g.TTL != time.Hour {
		t.Fatalf("ttl = %v, want the 1h cap", g.TTL)
	}
	// Over the cap is denied, naming max_ttl.
	_, err = p.Authorize("ci-bot", []string{"deploy"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "max_ttl") {
		t.Fatalf("err = %v, want a max_ttl denial", err)
	}
	// Exactly at the cap is allowed (the boundary belongs to the user).
	if _, err := p.Authorize("ci-bot", []string{"deploy"}, 15*time.Minute); err != nil {
		t.Fatalf("cap-exact ttl denied: %v", err)
	}
}

func TestWildcardAllowsAnyExplicitPrincipal(t *testing.T) {
	p := testPolicy(t)
	g, err := p.Authorize("root-op", []string{"emergency-root"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if g.Principals[0] != "emergency-root" {
		t.Fatalf("principals = %v", g.Principals)
	}
}

func TestWildcardGrantsNothingImplicitly(t *testing.T) {
	// An empty request under a wildcard rule must NOT expand to "*":
	// certificates always carry explicit principals.
	p := testPolicy(t)
	if _, err := p.Authorize("root-op", nil, time.Minute); err == nil {
		t.Fatal("expected a denial for an unnamed-principal request under wildcard")
	}
	// Nor does the wildcard bless malformed principal names.
	if _, err := p.Authorize("root-op", []string{"has space"}, time.Minute); err == nil {
		t.Fatal("expected a denial for a malformed principal")
	}
}

func TestDefaultsInheritance(t *testing.T) {
	p := testPolicy(t)
	// alice inherits extensions from defaults; ci-bot overrides to none.
	ga, _ := p.Describe("alice")
	if len(ga.Extensions) != 1 || ga.Extensions[0] != "permit-pty" {
		t.Fatalf("alice extensions = %v", ga.Extensions)
	}
	gc, _ := p.Describe("ci-bot")
	if len(gc.Extensions) != 0 {
		t.Fatalf("ci-bot extensions = %v, want none (explicit empty list)", gc.Extensions)
	}
	if gc.ForceCommand != "/usr/local/bin/deploy" {
		t.Fatalf("ci-bot force_command = %q", gc.ForceCommand)
	}
	if ga.MaxTTL != time.Hour || gc.MaxTTL != 15*time.Minute {
		t.Fatalf("max ttls = %v, %v", ga.MaxTTL, gc.MaxTTL)
	}
}

func TestFallbackMaxTTLWhenNothingSet(t *testing.T) {
	p, err := Parse([]byte(`{"version":1,"defaults":{},"users":{"a":{"principals":["a"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	g, _ := p.Describe("a")
	if g.MaxTTL != 8*time.Hour {
		t.Fatalf("fallback max ttl = %v, want 8h", g.MaxTTL)
	}
}

func TestParseRejectsBadDocuments(t *testing.T) {
	cases := map[string]string{
		// A typoed field ("max_tll") must be a hard error, not a silent fallback.
		"unknown field":      `{"version":1,"defaults":{},"users":{"a":{"principals":["a"],"max_tll":"1h"}}}`,
		"wrong version":      `{"version":2,"defaults":{},"users":{}}`,
		"bad max_ttl":        `{"version":1,"defaults":{"max_ttl":"soon"},"users":{}}`,
		"negative max_ttl":   `{"version":1,"defaults":{"max_ttl":"-1h"},"users":{}}`,
		"bad cidr":           `{"version":1,"defaults":{},"users":{"a":{"principals":["a"],"source_address":["10.0.0.0/99"]}}}`,
		"bad principal":      `{"version":1,"defaults":{},"users":{"a":{"principals":["no spaces allowed"]}}}`,
		"bad user name":      `{"version":1,"defaults":{},"users":{"user name":{"principals":["a"]}}}`,
		"default principals": `{"version":1,"defaults":{"principals":["a"]},"users":{}}`,
		"extension w/ space": `{"version":1,"defaults":{"extensions":["permit pty"]},"users":{}}`,
		"trailing data":      `{"version":1,"defaults":{},"users":{}} {}`,
		"not json":           `version: 1`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSourceAddressAcceptsCIDRAndBareIP(t *testing.T) {
	doc := `{"version":1,"defaults":{},"users":{"a":{"principals":["a"],
		"source_address":["10.0.0.0/8","192.168.1.7","fd00::/8"]}}}`
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatalf("valid addresses rejected: %v", err)
	}
}

func TestParseTTL(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"90s", 90 * time.Second, true},
		{"30m", 30 * time.Minute, true},
		{"2h30m", 2*time.Hour + 30*time.Minute, true},
		{"1d", 24 * time.Hour, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"", 0, false},
		{"0s", 0, false},   // zero is not a lifetime
		{"-5m", 0, false},  // negative
		{"1.5d", 0, false}, // fractional days are ambiguous; spell it 36h
		{"soon", 0, false},
	}
	for _, tc := range cases {
		got, err := ParseTTL(tc.in)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("ParseTTL(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Errorf("ParseTTL(%q) should fail", tc.in)
		}
	}
}

func TestFormatTTL(t *testing.T) {
	cases := map[time.Duration]string{
		time.Hour:                      "1h",
		30 * time.Minute:               "30m",
		2*time.Hour + 30*time.Minute:   "2h30m",
		90 * time.Second:               "1m30s",
		24 * time.Hour:                 "24h",
		15*time.Minute + 5*time.Second: "15m5s",
	}
	for d, want := range cases {
		if got := FormatTTL(d); got != want {
			t.Errorf("FormatTTL(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	p := testPolicy(t)
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(b)
	if err != nil {
		t.Fatalf("marshaled policy does not re-parse: %v", err)
	}
	if len(back.Users) != len(p.Users) {
		t.Fatalf("users lost in round trip: %d != %d", len(back.Users), len(p.Users))
	}
}

func TestDefaultPolicyIsValidAndDeniesEveryone(t *testing.T) {
	p := Default()
	if err := p.Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	if _, err := p.Authorize("anyone", []string{"anyone"}, time.Minute); err == nil {
		t.Fatal("the freshly initialized policy must deny all issuance")
	}
}
