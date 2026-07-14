// Package policy implements certclerk's principal policy: a strict,
// deny-by-default JSON document mapping users to the SSH principals
// they may hold, capped TTLs, extensions, source-address pins, and
// forced commands. All decisions are pure functions over the parsed
// document, so every rule is unit-testable without a CA on disk.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Wildcard in a rule's principal list allows any explicitly requested
// principal. It never grants anything implicitly: a request must still
// name its principals.
const Wildcard = "*"

// Rule is the per-user (or default) policy fragment. Pointer fields
// distinguish "unset, inherit the default" from "set to empty".
type Rule struct {
	Principals    []string  `json:"principals,omitempty"`
	MaxTTL        string    `json:"max_ttl,omitempty"`
	Extensions    *[]string `json:"extensions,omitempty"`
	SourceAddress []string  `json:"source_address,omitempty"`
	ForceCommand  string    `json:"force_command,omitempty"`
}

// Policy is the parsed policy.json document.
type Policy struct {
	Version  int             `json:"version"`
	Defaults Rule            `json:"defaults"`
	Users    map[string]Rule `json:"users"`
}

// Grant is the effective, validated authorization for one issuance.
type Grant struct {
	User          string
	Principals    []string
	TTL           time.Duration
	MaxTTL        time.Duration
	Extensions    []string
	SourceAddress []string
	ForceCommand  string
}

// DenyError explains a refused issuance. The CLI maps it to exit 1 so
// scripts can distinguish "policy said no" from operational failures.
type DenyError struct {
	User   string
	Reason string
}

func (e *DenyError) Error() string {
	return fmt.Sprintf("policy: denied for %q: %s", e.User, e.Reason)
}

// fallbackMaxTTL applies when neither the user rule nor defaults set
// max_ttl. Short by design: certclerk exists to end long-lived access.
const fallbackMaxTTL = 8 * time.Hour

var principalPattern = regexp.MustCompile(`^[A-Za-z0-9._@+-]+$`)

// Default returns the policy written by `certclerk init`: an 8h cap,
// permit-pty only, and no users — deny-by-default means a fresh CA can
// issue nothing until the operator grants principals explicitly.
func Default() *Policy {
	return &Policy{
		Version:  1,
		Defaults: Rule{MaxTTL: "8h", Extensions: &[]string{"permit-pty"}},
		Users:    map[string]Rule{},
	}
}

// Parse decodes and validates a policy document. Unknown fields are
// rejected: a typoed `max_tll` must fail loudly, not silently grant the
// fallback.
func Parse(b []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %v", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("policy: trailing data after the JSON document")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the whole document; the error names the first
// offending user and field.
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d (want 1)", p.Version)
	}
	if err := validateRule("defaults", &p.Defaults); err != nil {
		return err
	}
	if len(p.Defaults.Principals) > 0 {
		return fmt.Errorf("policy: defaults must not grant principals; grant them per user")
	}
	for user, rule := range p.Users {
		if !principalPattern.MatchString(user) {
			return fmt.Errorf("policy: invalid user name %q", user)
		}
		r := rule
		if err := validateRule("users."+user, &r); err != nil {
			return err
		}
	}
	return nil
}

func validateRule(where string, r *Rule) error {
	for _, pr := range r.Principals {
		if pr != Wildcard && !principalPattern.MatchString(pr) {
			return fmt.Errorf("policy: %s: invalid principal %q", where, pr)
		}
	}
	if r.MaxTTL != "" {
		if _, err := ParseTTL(r.MaxTTL); err != nil {
			return fmt.Errorf("policy: %s: max_ttl: %v", where, err)
		}
	}
	if r.Extensions != nil {
		for _, ext := range *r.Extensions {
			if ext == "" || strings.ContainsAny(ext, " \t\n") {
				return fmt.Errorf("policy: %s: invalid extension %q", where, ext)
			}
		}
	}
	for _, addr := range r.SourceAddress {
		if err := checkCIDR(addr); err != nil {
			return fmt.Errorf("policy: %s: source_address: %v", where, err)
		}
	}
	return nil
}

// checkCIDR accepts a CIDR prefix or a bare address, the two forms
// OpenSSH allows in a source-address critical option.
func checkCIDR(s string) error {
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	return fmt.Errorf("%q is neither a CIDR prefix nor an IP address", s)
}

// ParseTTL parses a duration limited to positive values, accepting Go
// syntax (90s, 30m, 2h30m) plus a whole-day suffix (7d) because cert
// lifetimes are usually discussed in days.
func ParseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

// FormatTTL renders a duration compactly (2h0m0s -> 2h, 30m0s -> 30m)
// for output. Only whole zero units are trimmed, so 1h30m stays intact.
func FormatTTL(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// resolve merges the user rule over the defaults into one effective rule.
func (p *Policy) resolve(user string) (*Rule, bool) {
	rule, ok := p.Users[user]
	if !ok {
		return nil, false
	}
	eff := rule
	if eff.MaxTTL == "" {
		eff.MaxTTL = p.Defaults.MaxTTL
	}
	if eff.Extensions == nil {
		eff.Extensions = p.Defaults.Extensions
	}
	if len(eff.SourceAddress) == 0 {
		eff.SourceAddress = p.Defaults.SourceAddress
	}
	if eff.ForceCommand == "" {
		eff.ForceCommand = p.Defaults.ForceCommand
	}
	return &eff, true
}

// Describe returns the effective rule for a user for `certclerk policy
// --user`, without authorizing anything.
func (p *Policy) Describe(user string) (*Grant, error) {
	eff, ok := p.resolve(user)
	if !ok {
		return nil, &DenyError{User: user, Reason: "user is not in the policy"}
	}
	g := &Grant{
		User:          user,
		Principals:    append([]string(nil), eff.Principals...),
		MaxTTL:        fallbackMaxTTL,
		SourceAddress: eff.SourceAddress,
		ForceCommand:  eff.ForceCommand,
	}
	if eff.MaxTTL != "" {
		g.MaxTTL, _ = ParseTTL(eff.MaxTTL)
	}
	if eff.Extensions != nil {
		g.Extensions = *eff.Extensions
	}
	return g, nil
}

// Authorize decides one issuance: user must exist, requested principals
// must be covered by the rule (or the rule's non-wildcard principals are
// granted when the request names none), and ttl must fit under max_ttl
// (0 requests the full cap). It returns the effective Grant or a
// *DenyError.
func (p *Policy) Authorize(user string, requested []string, ttl time.Duration) (*Grant, error) {
	g, err := p.Describe(user)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(g.Principals))
	wildcard := false
	for _, pr := range g.Principals {
		if pr == Wildcard {
			wildcard = true
			continue
		}
		allowed[pr] = true
	}
	if len(requested) == 0 {
		if len(allowed) == 0 {
			return nil, &DenyError{User: user, Reason: "no principals requested and the rule grants none by name"}
		}
		requested = make([]string, 0, len(allowed))
		for pr := range allowed {
			requested = append(requested, pr)
		}
		sort.Strings(requested)
	}
	for _, pr := range requested {
		if !principalPattern.MatchString(pr) {
			return nil, &DenyError{User: user, Reason: fmt.Sprintf("invalid principal %q", pr)}
		}
		if !allowed[pr] && !wildcard {
			return nil, &DenyError{User: user, Reason: fmt.Sprintf("principal %q is not allowed", pr)}
		}
	}
	if ttl == 0 {
		ttl = g.MaxTTL
	}
	if ttl > g.MaxTTL {
		return nil, &DenyError{User: user, Reason: fmt.Sprintf(
			"requested ttl %s exceeds max_ttl %s", FormatTTL(ttl), FormatTTL(g.MaxTTL))}
	}
	g.Principals = requested
	g.TTL = ttl
	return g, nil
}

// Marshal renders the policy as stable, indented JSON for policy.json.
func (p *Policy) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
