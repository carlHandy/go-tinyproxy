package config

import (
	"strings"
	"testing"
)

func TestParser_LocationPrefix(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location /api/ {
            proxy_pass http://api:3000
        }
    }
}`
	cfg, err := NewParser(strings.NewReader(input)).Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	vh := cfg.VHosts["example.com"]
	if len(vh.Locations) != 1 {
		t.Fatalf("got %d locations, want 1", len(vh.Locations))
	}
	loc := vh.Locations[0]
	if loc.Pattern != "/api/" {
		t.Errorf("Pattern = %q, want /api/", loc.Pattern)
	}
	if loc.MatchType != LocationMatchPrefix {
		t.Errorf("MatchType = %v, want Prefix", loc.MatchType)
	}
	if loc.Overrides.ProxyPass != "http://api:3000" {
		t.Errorf("ProxyPass = %q", loc.Overrides.ProxyPass)
	}
	if loc.Effective == nil {
		t.Error("Effective is nil — ApplyLocations was not called")
	}
	if loc.Effective.ProxyPass != "http://api:3000" {
		t.Errorf("Effective.ProxyPass = %q", loc.Effective.ProxyPass)
	}
}

func TestParser_LocationExact(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location = /health {
            proxy_pass http://health:8081
        }
    }
}`
	cfg, err := NewParser(strings.NewReader(input)).Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	loc := cfg.VHosts["example.com"].Locations[0]
	if loc.MatchType != LocationMatchExact {
		t.Errorf("MatchType = %v, want Exact", loc.MatchType)
	}
	if loc.Pattern != "/health" {
		t.Errorf("Pattern = %q, want /health", loc.Pattern)
	}
}

func TestParser_LocationRegex(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location ~ \.php$ {
            proxy_pass http://fpm:9000
        }
    }
}`
	cfg, err := NewParser(strings.NewReader(input)).Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	loc := cfg.VHosts["example.com"].Locations[0]
	if loc.MatchType != LocationMatchRegex {
		t.Errorf("MatchType = %v, want Regex", loc.MatchType)
	}
	if loc.Pattern != `\.php$` {
		t.Errorf("Pattern = %q", loc.Pattern)
	}
	if loc.compiledRegex == nil {
		t.Error("compiledRegex is nil — regex not compiled")
	}
	if !loc.compiledRegex.MatchString("/index.php") {
		t.Error("compiled regex should match /index.php")
	}
}

func TestParser_LocationRedirect(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location /old/ {
            redirect 301 https://example.com/new/
        }
    }
}`
	cfg, err := NewParser(strings.NewReader(input)).Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	loc := cfg.VHosts["example.com"].Locations[0]
	if loc.Overrides.Redirect == nil {
		t.Fatal("Redirect is nil")
	}
	if loc.Overrides.Redirect.Code != 301 {
		t.Errorf("Code = %d, want 301", loc.Overrides.Redirect.Code)
	}
	if loc.Overrides.Redirect.URL != "https://example.com/new/" {
		t.Errorf("URL = %q", loc.Overrides.Redirect.URL)
	}
}

func TestParser_LocationCompressionOff(t *testing.T) {
	input := `
vhosts {
    example.com {
        compression on
        location /api/ {
            proxy_pass http://api:3000
            compression off
        }
    }
}`
	cfg, err := NewParser(strings.NewReader(input)).Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	loc := cfg.VHosts["example.com"].Locations[0]
	if !loc.Overrides.SetCompression {
		t.Error("SetCompression should be true")
	}
	if loc.Overrides.Compression {
		t.Error("Compression should be false")
	}
	if loc.Effective.Compression {
		t.Error("Effective.Compression should be false")
	}
}

func TestParser_LocationSecurityOverride(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location /api/ {
            proxy_pass http://api:3000
            security {
                rate_limit {
                    requests 1000
                    window 1m
                }
            }
        }
    }
}`
	cfg, err := NewParser(strings.NewReader(input)).Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	loc := cfg.VHosts["example.com"].Locations[0]
	if !loc.Overrides.SetSecurity {
		t.Error("SetSecurity should be true")
	}
	if loc.Overrides.Security.RateLimit.Requests != 1000 {
		t.Errorf("RateLimit.Requests = %d, want 1000", loc.Overrides.Security.RateLimit.Requests)
	}
}

func TestParser_LocationFastCGI(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www/html
        location ~ \.php$ {
            fastcgi {
                pass 127.0.0.1:9000
                index index.php
                param SCRIPT_FILENAME /var/www/html/$fastcgi_script_name
            }
        }
    }
}`
	cfg, err := NewParser(strings.NewReader(input)).Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	loc := cfg.VHosts["example.com"].Locations[0]
	if loc.Overrides.FastCGI.Pass != "127.0.0.1:9000" {
		t.Errorf("FastCGI.Pass = %q", loc.Overrides.FastCGI.Pass)
	}
	if loc.Overrides.FastCGI.Index != "index.php" {
		t.Errorf("FastCGI.Index = %q", loc.Overrides.FastCGI.Index)
	}
	if len(loc.Overrides.FastCGI.Params) != 1 {
		t.Errorf("FastCGI.Params len = %d, want 1", len(loc.Overrides.FastCGI.Params))
	}
}

func TestParser_LocationNoHandlerError(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location /api/ {
            compression off
        }
    }
}`
	_, err := NewParser(strings.NewReader(input)).Parse()
	if err == nil {
		t.Error("expected error for location with no handler, got nil")
	}
}

func TestParser_LocationInvalidRegexError(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location ~ [invalid {
            proxy_pass http://api:3000
        }
    }
}`
	_, err := NewParser(strings.NewReader(input)).Parse()
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestParser_LocationUnknownModifierError(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location ^~ /api/ {
            proxy_pass http://api:3000
        }
    }
}`
	_, err := NewParser(strings.NewReader(input)).Parse()
	if err == nil {
		t.Error("expected error for unsupported ^~ modifier, got nil")
	}
}

func TestParser_MultipleLocations(t *testing.T) {
	input := `
vhosts {
    example.com {
        root /var/www
        location = /health {
            proxy_pass http://health:8081
        }
        location /api/ {
            proxy_pass http://api:3000
        }
        location ~ \.php$ {
            proxy_pass http://fpm:9000
        }
    }
}`
	cfg, err := NewParser(strings.NewReader(input)).Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	locs := cfg.VHosts["example.com"].Locations
	if len(locs) != 3 {
		t.Fatalf("got %d locations, want 3", len(locs))
	}
	if locs[0].MatchType != LocationMatchExact {
		t.Errorf("locs[0] should be exact")
	}
	if locs[1].MatchType != LocationMatchPrefix {
		t.Errorf("locs[1] should be prefix")
	}
	if locs[2].MatchType != LocationMatchRegex {
		t.Errorf("locs[2] should be regex")
	}
}
