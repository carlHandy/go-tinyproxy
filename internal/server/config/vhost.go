package config

import (
	"time"

	"tinyproxy/internal/cache"
	"tinyproxy/internal/loadbalancer"
)

type SecurityConfig struct {
	Headers struct {
		FrameOptions  string
		ContentType   string
		XSSProtection string
		CSP           string
		HSTS          string
	}
	RateLimit struct {
		Enabled  bool
		Requests int
		Window   time.Duration
	}
	MaxBodySize int64
}

type FastCGIConfig struct {
	Enabled bool
	Pass    string
	Index   string
	Params  map[string]string
}

// BotProtectionConfig controls per-vhost bot detection settings.
type BotProtectionConfig struct {
	Enabled       bool
	BlockScanners bool
	Honeypot      bool
	BlockedAgents []string
	AllowedAgents []string
	BlockedPaths  []string
}

type VirtualHost struct {
	Hostname    string
	Port        int
	Root        string
	ProxyPass   string
	Redirect    *RedirectConfig
	SSL         bool
	CertFile    string
	KeyFile     string
	Compression bool
	Security    SecurityConfig
	MaxBodySize int64
	SOCKS5      struct {
		Enabled  bool
		Address  string
		Username string
		Password string
	}
	FastCGI       FastCGIConfig
	BotProtection BotProtectionConfig
	Cache         cache.CacheConfig
	Upstream      loadbalancer.LBConfig
	Locations     []LocationConfig
}

func NewVirtualHost() *VirtualHost {
	vh := &VirtualHost{
		Compression: true,
		Security: SecurityConfig{
			Headers: struct {
				FrameOptions  string
				ContentType   string
				XSSProtection string
				CSP           string
				HSTS          string
			}{
				FrameOptions:  "SAMEORIGIN",
				ContentType:   "nosniff",
				XSSProtection: "1; mode=block",
				CSP:           "",
				HSTS:          "max-age=31536000; includeSubDomains",
			},
			RateLimit: struct {
				Enabled  bool
				Requests int
				Window   time.Duration
			}{
				Enabled:  true,
				Requests: 100,
				Window:   time.Minute,
			},
		},
		MaxBodySize: 10 << 20,
		Cache:       cache.DefaultCacheConfig(),
		Upstream:    loadbalancer.DefaultLBConfig(),
	}
	return vh
}

type ServerConfig struct {
	VHosts map[string]*VirtualHost
}

func NewServerConfig() *ServerConfig {
	config := &ServerConfig{
		VHosts: make(map[string]*VirtualHost),
	}

	defaultVHost := &VirtualHost{
		Hostname:    "_",
		Port:        8080,
		Compression: true,
		Root:        "static",
		Security: SecurityConfig{
			Headers: struct {
				FrameOptions  string
				ContentType   string
				XSSProtection string
				CSP           string
				HSTS          string
			}{
				FrameOptions:  "SAMEORIGIN",
				ContentType:   "nosniff",
				XSSProtection: "1; mode=block",
				CSP:           "default-src 'self'",
				HSTS:          "max-age=31536000; includeSubDomains",
			},
			RateLimit: struct {
				Enabled  bool
				Requests int
				Window   time.Duration
			}{
				Enabled:  true,
				Requests: 100,
				Window:   time.Minute,
			},
			MaxBodySize: 10 << 20,
		},
		SOCKS5: struct {
			Enabled  bool
			Address  string
			Username string
			Password string
		}{
			Enabled: true,
			Address: "127.0.0.1:1080",
		},
	}

	config.VHosts["default"] = defaultVHost
	config.VHosts["default_ssl"] = defaultVHost

	return config
}
