package pki

import "testing"

func TestGenerateCA(t *testing.T) {
	for _, testCase := range []struct {
		name               string
		config             *CAConfig
		extNameConstraints bool
	}{
		{
			name:               "without-permitted-dns",
			config:             &CAConfig{CommonName: "simple.example.com"},
			extNameConstraints: false,
		},
		{
			name:               "domain-restrained",
			config:             &CAConfig{CommonName: "ca.example.com", PermittedDNSDomains: []string{".example"}},
			extNameConstraints: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ca, err := GenerateCA(testCase.config)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ca.Certificate.Subject.CommonName != testCase.config.CommonName {
				// smoke test
				t.Errorf("unexpected certificate: %v", ca.Certificate)
			}
			if len(ca.Certificate.PermittedDNSDomains) > 0 {
				if !testCase.extNameConstraints {
					t.Errorf("unexpected name constraints: %v", ca.Certificate)
				}
				if !ca.Certificate.PermittedDNSDomainsCritical {
					t.Errorf("name constraints not critical")
				}
				if len(ca.Certificate.PermittedDNSDomains) != len(testCase.config.PermittedDNSDomains) {
					t.Errorf("mismatched length of premitted dns domains: expected %v but got %v",
						len(testCase.config.PermittedDNSDomains), len(ca.Certificate.PermittedDNSDomains))
				}
				for i := range ca.Certificate.PermittedDNSDomains {
					if ca.Certificate.PermittedDNSDomains[i] != testCase.config.PermittedDNSDomains[i] {
						t.Errorf("mismatched permitted dns domain: expected %v but got %v",
							testCase.config.PermittedDNSDomains[i], ca.Certificate.PermittedDNSDomains[i])
					}
				}
			} else {
				if testCase.extNameConstraints {
					t.Errorf("missing name constraints: %v", ca.Certificate)
				}
			}
		})
	}
}
