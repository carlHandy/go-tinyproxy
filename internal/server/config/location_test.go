package config

import (
	"regexp"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func mustCompileRegex(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("mustCompileRegex(%q): %v", pattern, err)
	}
	return re
}

// ── MatchLocation ─────────────────────────────────────────────────────────────

func TestMatchLocation_NilOnEmpty(t *testing.T) {
	if got := MatchLocation(nil, "/api/users"); got != nil {
		t.Errorf("expected nil for empty locations, got %+v", got)
	}
}

func TestMatchLocation_ExactWinsOverPrefix(t *testing.T) {
	locs := []LocationConfig{
		{Pattern: "/api/", MatchType: LocationMatchPrefix},
		{Pattern: "/api/health", MatchType: LocationMatchExact},
	}
	got := MatchLocation(locs, "/api/health")
	if got == nil {
		t.Fatal("expected a match, got nil")
	}
	if got.MatchType != LocationMatchExact {
		t.Errorf("expected exact match, got MatchType=%v", got.MatchType)
	}
	if got.Pattern != "/api/health" {
		t.Errorf("Pattern = %q, want /api/health", got.Pattern)
	}
}

func TestMatchLocation_LongestPrefixWins(t *testing.T) {
	locs := []LocationConfig{
		{Pattern: "/api/", MatchType: LocationMatchPrefix},
		{Pattern: "/api/v2/", MatchType: LocationMatchPrefix},
		{Pattern: "/", MatchType: LocationMatchPrefix},
	}
	got := MatchLocation(locs, "/api/v2/users")
	if got == nil {
		t.Fatal("expected a match, got nil")
	}
	if got.Pattern != "/api/v2/" {
		t.Errorf("Pattern = %q, want /api/v2/", got.Pattern)
	}
}

func TestMatchLocation_RegexBeatsPrefix(t *testing.T) {
	locs := []LocationConfig{
		{Pattern: "/", MatchType: LocationMatchPrefix},
		{Pattern: `\.php$`, MatchType: LocationMatchRegex, compiledRegex: mustCompileRegex(t, `\.php$`)},
	}
	got := MatchLocation(locs, "/index.php")
	if got == nil {
		t.Fatal("expected a match, got nil")
	}
	if got.MatchType != LocationMatchRegex {
		t.Errorf("expected regex to beat prefix, got MatchType=%v", got.MatchType)
	}
}

func TestMatchLocation_RegexDeclarationOrderWins(t *testing.T) {
	locs := []LocationConfig{
		{Pattern: `/api/.*`, MatchType: LocationMatchRegex, compiledRegex: mustCompileRegex(t, `/api/.*`)},
		{Pattern: `/api/v2/.*`, MatchType: LocationMatchRegex, compiledRegex: mustCompileRegex(t, `/api/v2/.*`)},
	}
	got := MatchLocation(locs, "/api/v2/users")
	if got == nil {
		t.Fatal("expected a match, got nil")
	}
	if got.Pattern != `/api/.*` {
		t.Errorf("first regex should win, got %q", got.Pattern)
	}
}

func TestMatchLocation_NilWhenNoMatch(t *testing.T) {
	locs := []LocationConfig{
		{Pattern: "/api/", MatchType: LocationMatchPrefix},
	}
	got := MatchLocation(locs, "/admin/")
	if got != nil {
		t.Errorf("expected nil for no match, got %+v", got)
	}
}

func TestMatchLocation_PrefixCandidateBeatsUnmatchedRegex(t *testing.T) {
	locs := []LocationConfig{
		{Pattern: "/api/", MatchType: LocationMatchPrefix},
		{Pattern: `\.php$`, MatchType: LocationMatchRegex, compiledRegex: mustCompileRegex(t, `\.php$`)},
	}
	// /api/users doesn't match \.php$, so prefix candidate wins
	got := MatchLocation(locs, "/api/users")
	if got == nil {
		t.Fatal("expected prefix candidate, got nil")
	}
	if got.MatchType != LocationMatchPrefix {
		t.Errorf("expected prefix, got MatchType=%v", got.MatchType)
	}
}

func TestMatchLocation_PrefixDoesNotMatchBoundaryViolation(t *testing.T) {
	locs := []LocationConfig{
		{Pattern: "/api", MatchType: LocationMatchPrefix},
	}
	got := MatchLocation(locs, "/apifoo")
	if got != nil {
		t.Errorf("expected nil for /apifoo against /api prefix, got match on %q", got.Pattern)
	}
}

// ── helpers for MergeLocation/ApplyLocations tests ───────────────────────────

func baseVHost() *VirtualHost {
	vh := NewVirtualHost()
	vh.Hostname = "example.com"
	vh.Root = "/var/www"
	vh.Compression = true
	vh.Security.Headers.FrameOptions = "SAMEORIGIN"
	return vh
}

// ── MergeLocation ─────────────────────────────────────────────────────────────

func TestMergeLocation_ProxyPassReplacesRoot(t *testing.T) {
	base := baseVHost()
	loc := &LocationConfig{
		Pattern:   "/api/",
		MatchType: LocationMatchPrefix,
		Overrides: LocationOverrides{ProxyPass: "http://api:3000"},
	}
	eff := MergeLocation(base, loc)
	if eff.ProxyPass != "http://api:3000" {
		t.Errorf("ProxyPass = %q, want http://api:3000", eff.ProxyPass)
	}
	if eff.Root != "" {
		t.Errorf("Root should be cleared when ProxyPass is set, got %q", eff.Root)
	}
}

func TestMergeLocation_RedirectClears(t *testing.T) {
	base := baseVHost()
	loc := &LocationConfig{
		Pattern:   "/old/",
		MatchType: LocationMatchPrefix,
		Overrides: LocationOverrides{
			Redirect: &RedirectConfig{Code: 301, URL: "https://new.example.com/"},
		},
	}
	eff := MergeLocation(base, loc)
	if eff.Redirect == nil {
		t.Fatal("Redirect is nil")
	}
	if eff.Redirect.Code != 301 {
		t.Errorf("Code = %d, want 301", eff.Redirect.Code)
	}
	if eff.Root != "" {
		t.Errorf("Root should be cleared, got %q", eff.Root)
	}
}

func TestMergeLocation_CompressionOverride(t *testing.T) {
	base := baseVHost()
	base.Compression = true
	loc := &LocationConfig{
		Pattern:   "/api/",
		MatchType: LocationMatchPrefix,
		Overrides: LocationOverrides{
			ProxyPass:      "http://api:3000",
			SetCompression: true,
			Compression:    false,
		},
	}
	eff := MergeLocation(base, loc)
	if eff.Compression {
		t.Error("Compression should be false after override")
	}
}

func TestMergeLocation_CompressionNotOverriddenWhenSetIsFalse(t *testing.T) {
	base := baseVHost()
	base.Compression = true
	loc := &LocationConfig{
		Pattern:   "/api/",
		Overrides: LocationOverrides{ProxyPass: "http://api:3000"},
	}
	eff := MergeLocation(base, loc)
	if !eff.Compression {
		t.Error("Compression should be inherited (true) when not overridden")
	}
}

func TestMergeLocation_InheritedSecurityHeadersCarryThrough(t *testing.T) {
	base := baseVHost()
	base.Security.Headers.FrameOptions = "DENY"
	loc := &LocationConfig{
		Pattern:   "/api/",
		Overrides: LocationOverrides{ProxyPass: "http://api:3000"},
	}
	eff := MergeLocation(base, loc)
	if eff.Security.Headers.FrameOptions != "DENY" {
		t.Errorf("FrameOptions not inherited: %q", eff.Security.Headers.FrameOptions)
	}
}

func TestMergeLocation_SecurityOverrideReplacesWholesale(t *testing.T) {
	base := baseVHost()
	base.Security.Headers.FrameOptions = "DENY"
	base.Security.RateLimit.Requests = 100

	newSec := SecurityConfig{}
	newSec.RateLimit.Requests = 1000
	newSec.RateLimit.Window = time.Minute

	loc := &LocationConfig{
		Pattern: "/api/",
		Overrides: LocationOverrides{
			ProxyPass:   "http://api:3000",
			SetSecurity: true,
			Security:    newSec,
		},
	}
	eff := MergeLocation(base, loc)
	if eff.Security.RateLimit.Requests != 1000 {
		t.Errorf("RateLimit.Requests = %d, want 1000", eff.Security.RateLimit.Requests)
	}
	// FrameOptions is NOT inherited when security block is replaced wholesale
	if eff.Security.Headers.FrameOptions != "" {
		t.Errorf("FrameOptions should be cleared by wholesale security override, got %q", eff.Security.Headers.FrameOptions)
	}
}

func TestMergeLocation_NoLocationsOnEffective(t *testing.T) {
	base := baseVHost()
	base.Locations = []LocationConfig{{Pattern: "/sub/"}}
	loc := &LocationConfig{
		Pattern:   "/api/",
		Overrides: LocationOverrides{ProxyPass: "http://api:3000"},
	}
	eff := MergeLocation(base, loc)
	if len(eff.Locations) != 0 {
		t.Errorf("effective vhost should have no nested Locations, got %d", len(eff.Locations))
	}
}

// ── ApplyLocations ────────────────────────────────────────────────────────────

func TestApplyLocations_SetsEffective(t *testing.T) {
	vh := NewVirtualHost()
	vh.Root = "/var/www"
	vh.Locations = []LocationConfig{
		{
			Pattern:   "/api/",
			MatchType: LocationMatchPrefix,
			Overrides: LocationOverrides{ProxyPass: "http://api:3000"},
		},
	}
	if err := ApplyLocations(vh); err != nil {
		t.Fatalf("ApplyLocations: %v", err)
	}
	eff := vh.Locations[0].Effective
	if eff == nil {
		t.Fatal("Effective is nil after ApplyLocations")
	}
	if eff.ProxyPass != "http://api:3000" {
		t.Errorf("Effective.ProxyPass = %q", eff.ProxyPass)
	}
}

func TestApplyLocations_CompilesRegex(t *testing.T) {
	vh := NewVirtualHost()
	vh.Root = "/var/www"
	vh.Locations = []LocationConfig{
		{
			Pattern:   `\.php$`,
			MatchType: LocationMatchRegex,
			Overrides: LocationOverrides{
				FastCGI: FastCGIConfig{Pass: "127.0.0.1:9000", Params: map[string]string{}},
			},
		},
	}
	if err := ApplyLocations(vh); err != nil {
		t.Fatalf("ApplyLocations: %v", err)
	}
	loc := &vh.Locations[0]
	if loc.compiledRegex == nil {
		t.Fatal("compiledRegex is nil after ApplyLocations")
	}
	if !loc.compiledRegex.MatchString("/index.php") {
		t.Error("compiled regex should match /index.php")
	}
}

func TestApplyLocations_InvalidRegexReturnsError(t *testing.T) {
	vh := NewVirtualHost()
	vh.Root = "/var/www"
	vh.Locations = []LocationConfig{
		{
			Pattern:   `[invalid`,
			MatchType: LocationMatchRegex,
			Overrides: LocationOverrides{ProxyPass: "http://api:3000"},
		},
	}
	if err := ApplyLocations(vh); err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestApplyLocations_EmptyLocationsNoError(t *testing.T) {
	vh := NewVirtualHost()
	vh.Root = "/var/www"
	if err := ApplyLocations(vh); err != nil {
		t.Errorf("ApplyLocations with no locations: %v", err)
	}
}
