package config

import (
	"regexp"
	"testing"
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
