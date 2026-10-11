package patterns

import (
	"strings"
	"testing"
)

func TestPIIPatternsCaptureValues(t *testing.T) {
	manager := NewPatternManager()
	if err := manager.LoadPatterns([]string{"pii"}, nil); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "serial_number", input: `serial = "NX7Q-4M9K-2P8R"`, expected: "NX7Q-4M9K-2P8R"},
		{name: "us_zip_code", input: "postal_code = 94107", expected: "94107"},
		{name: "us_zip_code", input: "post_code = 02139", expected: "02139"},
		{name: "ipv4_address", input: `server_ip = "10.0.0.5"`, expected: "10.0.0.5"},
		{name: "ipv6_address", input: `ipv6_address = "fd12:3456::42"`, expected: "fd12:3456::42"},
		{name: "ipv6_address", input: `ipv6_addr = "::ffff:10.0.0.5"`, expected: "::ffff:10.0.0.5"},
		{name: "mac_address", input: `hw_addr = "02:42:ac:11:00:02"`, expected: "02:42:ac:11:00:02"},
		{name: "mac_address", input: `mac_address = "02-42-AC-11-00-02"`, expected: "02-42-AC-11-00-02"},
		{name: "phone_number", input: `phone = "+1 404-287-6391"`, expected: "+1 404-287-6391"},
		{name: "person_name", input: `customer_name = "Marina Costa"`, expected: "Marina Costa"},
		{name: "person_name", input: `O cliente é João da Silva`, expected: "João da Silva"},
		{name: "person_name", input: `full_name = "Érica d'Ávila"`, expected: "Érica d'Ávila"},
		{name: "person_name", input: `beneficiary is Renée O'Connor`, expected: "Renée O'Connor"},
		{name: "person_name", input: `{"customer_name":"Mário d'Ávila"}`, expected: "Mário d'Ávila"},
		{name: "person_name", input: `{'patient_name': 'João da Silva'}`, expected: "João da Silva"},
		{name: "person_name", input: `customer_name = "John Doe"`, expected: "John Doe"},
	}

	compiled := manager.GetCompiledPatterns()
	for _, test := range tests {
		pattern, ok := compiled[test.name]
		if !ok {
			t.Fatalf("pattern %q was not loaded", test.name)
		}
		match := pattern.Regex.FindStringSubmatch(test.input)
		if len(match) < 2 || match[1] != test.expected {
			t.Fatalf("pattern %q captured %#v, expected %q", test.name, match, test.expected)
		}
	}
}

func TestPIIPatternsRejectOverbroadShapes(t *testing.T) {
	manager := NewPatternManager()
	if err := manager.LoadPatterns([]string{"pii"}, nil); err != nil {
		t.Fatal(err)
	}
	compiled := manager.GetCompiledPatterns()
	tests := []struct {
		name  string
		input string
	}{
		{name: "phone_number", input: "phone=2121234567"},
		{name: "phone_number", input: "phone=40428763912"},
		{name: "ipv4_address", input: "server_ip=10.0.0.500"},
		{name: "ipv6_address", input: "ipv6_address=fd12:3456::42garbage"},
		{name: "mac_address", input: "mac_address=02:42:ac:11:00:02:ff"},
		{name: "serial_number", input: "serial=" + strings.Repeat("A", 40) + "-EXTRA"},
		{name: "us_zip_code", input: "address=94107"},
	}
	for _, test := range tests {
		if match := compiled[test.name].Regex.FindStringSubmatch(test.input); match != nil {
			t.Errorf("pattern %q accepted overbroad input %q: %#v", test.name, test.input, match)
		}
	}
}

func TestPersonNamePatternRequiresNearbyIdentityContext(t *testing.T) {
	manager := NewPatternManager()
	if err := manager.LoadPatterns([]string{"pii"}, nil); err != nil {
		t.Fatal(err)
	}

	pattern, ok := manager.GetCompiledPatterns()["person_name"]
	if !ok {
		t.Fatal("person_name pattern was not loaded")
	}

	for _, input := range []string{
		`const command = "Docker Compose"`,
		`name = "Runtime Config"`,
		`project_name = "Secret Hound"`,
		`The Customer Success Team owns this service.`,
		`recipient_id = "Marina Costa"`,
	} {
		if match := pattern.Regex.FindStringSubmatch(input); len(match) > 0 {
			t.Errorf("unexpected person_name match for %q: %#v", input, match)
		}
	}
}
