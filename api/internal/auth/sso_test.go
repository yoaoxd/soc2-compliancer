package auth

import "testing"

func TestAllowsEmail(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *Service
		email  string
		allowed bool
	}{
		{"empty allowlist allows all", &Service{}, "x@evil.com", true},
		{"exact domain match", &Service{allowedDomains: []string{"gmail.com"}}, "me@gmail.com", true},
		{"exact email match", &Service{allowedDomains: []string{"bob@corp.com"}}, "bob@corp.com", true},
		{"other email rejected when domain allowed", &Service{allowedDomains: []string{"corp.com"}}, "alice@other.com", false},
		{"no-at rejected", &Service{allowedDomains: []string{"corp.com"}}, "not-an-email", false},
		{"case insensitive", &Service{allowedDomains: []string{"CORP.COM"}}, "alice@corp.com", true},
		{"leading dot trimmed", &Service{allowedDomains: []string{".corp.com"}}, "alice@corp.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.allowsEmail(tc.email); got != tc.allowed {
				t.Fatalf("allowsEmail(%q): got %v, want %v", tc.email, got, tc.allowed)
			}
		})
	}
}