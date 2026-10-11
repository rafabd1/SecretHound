package utils

import "testing"

func TestExtractDomainHandlesPortsAndIPv6(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{name: "hostname", url: "https://example.com/app.js", expected: "example.com"},
		{name: "port", url: "https://example.com:8443/app.js", expected: "example.com"},
		{name: "ipv6", url: "https://[2001:db8::1]:8443/app.js", expected: "2001:db8::1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := ExtractDomain(test.url)
			if err != nil {
				t.Fatal(err)
			}
			if actual != test.expected {
				t.Fatalf("ExtractDomain(%q) = %q, want %q", test.url, actual, test.expected)
			}
		})
	}
}
