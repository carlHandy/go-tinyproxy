package config

import (
	"regexp"

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
