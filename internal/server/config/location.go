package config

import (
	"fmt"
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
		pat := locations[i].Pattern
		if path == pat || strings.HasPrefix(path, strings.TrimSuffix(pat, "/")+"/") {
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

// MergeLocation clones base and applies location overrides to produce the
// effective VirtualHost for requests matching loc.
func MergeLocation(base *VirtualHost, loc *LocationConfig) *VirtualHost {
	eff := *base
	eff.Locations = nil // effective vhosts don't carry nested locations
	eff.Redirect = nil  // clear vhost-level redirect before applying handler

	o := loc.Overrides
	switch {
	case o.ProxyPass != "":
		eff.ProxyPass = o.ProxyPass
		eff.Root = ""
		eff.Redirect = nil
		eff.FastCGI = FastCGIConfig{}
		eff.Upstream = loadbalancer.DefaultLBConfig()
	case o.Root != "":
		eff.Root = o.Root
		eff.ProxyPass = ""
		eff.Redirect = nil
		eff.FastCGI = FastCGIConfig{}
		eff.Upstream = loadbalancer.DefaultLBConfig()
	case o.Redirect != nil:
		eff.Redirect = o.Redirect
		eff.ProxyPass = ""
		eff.Root = ""
		eff.FastCGI = FastCGIConfig{}
		eff.Upstream = loadbalancer.DefaultLBConfig()
	case o.FastCGI.Pass != "":
		eff.FastCGI = o.FastCGI
		eff.ProxyPass = ""
		eff.Root = ""
		eff.Redirect = nil
		eff.Upstream = loadbalancer.DefaultLBConfig()
	case len(o.Upstream.Backends) > 0:
		eff.Upstream = o.Upstream
		eff.ProxyPass = ""
		eff.Root = ""
		eff.Redirect = nil
		eff.FastCGI = FastCGIConfig{}
	}

	if o.SetCompression {
		eff.Compression = o.Compression
	}
	if o.SetSecurity {
		eff.Security = o.Security
	}
	if o.SetBotProtection {
		eff.BotProtection = o.BotProtection
	}
	if o.SetCache {
		eff.Cache = o.Cache
	}

	return &eff
}

// ApplyLocations compiles regexes and pre-computes effective VirtualHosts for
// all locations. Must be called after the parent vhost is fully parsed.
func ApplyLocations(vhost *VirtualHost) error {
	for i := range vhost.Locations {
		loc := &vhost.Locations[i]
		if loc.MatchType == LocationMatchRegex {
			re, err := regexp.Compile(loc.Pattern)
			if err != nil {
				return fmt.Errorf("location %q: invalid regex: %w", loc.Pattern, err)
			}
			loc.compiledRegex = re
		}
		loc.Effective = MergeLocation(vhost, loc)
	}
	return nil
}
