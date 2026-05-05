package config

import (
	"regexp"
	"strings"

	"tinyproxy/internal/cache"
	"tinyproxy/internal/loadbalancer"
)

type LocationMatchType int

const (
	LocationMatchPrefix LocationMatchType = iota // no modifier, longest-match
	LocationMatchExact                            // =
	LocationMatchRegex                            // ~
)

type RedirectConfig struct {
	Code int
	URL  string
}

// LocationOverrides holds only what was explicitly set in the location block.
// Set* booleans distinguish "explicitly set to false" from "not set".
type LocationOverrides struct {
	// Handler — exactly one should be non-zero
	ProxyPass string
	Root      string
	Redirect  *RedirectConfig
	FastCGI   FastCGIConfig
	Upstream  loadbalancer.LBConfig

	// Middleware overrides
	SetCompression bool
	Compression    bool

	SetSecurity bool
	Security    SecurityConfig

	SetBotProtection bool
	BotProtection    BotProtectionConfig

	SetCache bool
	Cache    cache.CacheConfig
}

type LocationConfig struct {
	Pattern       string
	MatchType     LocationMatchType
	Overrides     LocationOverrides
	compiledRegex *regexp.Regexp // set by ApplyLocations; nil for non-regex
	Effective     *VirtualHost   // pre-computed by ApplyLocations
}

// MatchLocation finds the best-matching location for path using the priority:
// 1. exact (=) match wins immediately
// 2. regex (~) first-matching in declaration order beats prefix candidate
// 3. longest plain-prefix candidate as fallback
func MatchLocation(locations []LocationConfig, path string) *LocationConfig {
	// Pass 1: exact
	for i := range locations {
		if locations[i].MatchType == LocationMatchExact && locations[i].Pattern == path {
			return &locations[i]
		}
	}

	// Pass 2: longest prefix candidate
	var best *LocationConfig
	for i := range locations {
		if locations[i].MatchType != LocationMatchPrefix {
			continue
		}
		if strings.HasPrefix(path, locations[i].Pattern) {
			if best == nil || len(locations[i].Pattern) > len(best.Pattern) {
				best = &locations[i]
			}
		}
	}

	// Pass 3: regex, first match wins (beats prefix candidate)
	for i := range locations {
		if locations[i].MatchType == LocationMatchRegex && locations[i].compiledRegex != nil {
			if locations[i].compiledRegex.MatchString(path) {
				return &locations[i]
			}
		}
	}

	return best
}
