package detector

import (
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/validation"
	"github.com/rafabd1/SecretHound/output"
)

func TestCredentialURIsReachDetectionAsCompleteValues(t *testing.T) {
	manager := patterns.NewPatternManager()
	if err := manager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   100,
	})

	tests := []struct {
		name        string
		patternType string
		value       string
	}{
		{
			name:        "mongodb srv",
			patternType: "mongodb_uri",
			value:       "mongodb+srv://deploy:A7kQ9mX2vR5tY8uP3nD6@cluster.internal/orders?retryWrites=true",
		},
		{
			name:        "mongodb standard with port",
			patternType: "mongodb_uri",
			value:       "mongodb://deploy:A7kQ9mX2vR5tY8uP3nD6@db.internal:27017/orders",
		},
		{
			name:        "mysql without database",
			patternType: "mysql_connection_string",
			value:       "mysql://deploy:A7kQ9mX2vR5tY8uP3nD6@db.internal:3306",
		},
		{
			name:        "postgres with database",
			patternType: "postgresql_connection_string",
			value:       "postgresql://deploy:A7kQ9mX2vR5tY8uP3nD6@db.internal/orders",
		},
		{
			name:        "redis empty username",
			patternType: "redis_url",
			value:       "rediss://:A7kQ9mX2vR5tY8uP3nD6@cache.internal:6380/0",
		},
		{
			name:        "short mongodb",
			patternType: "mongodb_uri",
			value:       "mongodb://u:p@h",
		},
		{
			name:        "shortest mysql without database",
			patternType: "mysql_connection_string",
			value:       "mysql://a:b@c",
		},
		{
			name:        "short postgres",
			patternType: "postgresql_connection_string",
			value:       "postgres://u:p@h/d",
		},
		{
			name:        "short redis",
			patternType: "redis_url",
			value:       "redis://:p@h",
		},
		{
			name:        "uppercase IPv6 host",
			patternType: "postgresql_connection_string",
			value:       "POSTGRESQL://u:p@[FE80::1]/d",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := "DATABASE_URL=\"" + test.value + "\""
			findings, err := detector.DetectSecrets(content, "file://production.env")
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range findings {
				if item.Type == test.patternType && item.Value == test.value {
					return
				}
			}
			t.Fatalf("%s did not detect complete credential URI %q: %+v", test.patternType, test.value, findings)
		})
	}
}

func TestCredentialURIStopsBeforeFollowingCode(t *testing.T) {
	manager := patterns.NewPatternManager()
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   100,
	})
	value := "postgresql://deploy:A7kQ9mX2vR5tY8uP3nD6@db.internal/app"
	findings, err := detector.DetectSecrets("const db="+value+";doWork()", "file://config.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range findings {
		if item.Type == "postgresql_connection_string" {
			if item.Value != value {
				t.Fatalf("credential URI swallowed following code: %q", item.Value)
			}
			return
		}
	}
	t.Fatalf("credential URI was not detected: %+v", findings)
}

func TestMSSQLConnectionStringSupportsAliasesAndOrder(t *testing.T) {
	manager := patterns.NewPatternManager()
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   100,
	})
	value := "PWD={S3cr3t!;v2};Initial Catalog=app;UID=svc;Data Source=db01;"
	pattern, ok := manager.GetCompiledPatterns()["mssql_connection_string"]
	if !ok {
		t.Fatal("mssql_connection_string was not loaded")
	}
	match := pattern.Regex.FindStringSubmatch(value)
	if len(match) < 2 {
		t.Fatalf("MSSQL regex did not match %q", value)
	}
	if decision := validation.EvaluateCandidate(pattern.Name, pattern, match[1], "DATABASE_URL=\""+value+"\"", validation.Options{LocalMode: true}); !decision.Valid {
		t.Fatalf("MSSQL match failed validation: match=%q decision=%+v", match[1], decision)
	}
	content := "DATABASE_URL=\"" + value + "\""
	contentMatch := pattern.Regex.FindStringSubmatch(content)
	if len(contentMatch) < 2 {
		t.Fatalf("MSSQL regex did not match content %q", content)
	}
	if contentMatch[1] != value {
		t.Fatalf("MSSQL regex captured %q, want %q", contentMatch[1], value)
	}
	findings, err := detector.DetectSecrets(content, "file://production.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range findings {
		if item.Type == "mssql_connection_string" && item.Value == value {
			return
		}
	}
	t.Fatalf("MSSQL connection string was not detected: %+v", findings)
}

func TestMSSQLIntegratedSecurityWithoutPasswordIsNotASecret(t *testing.T) {
	manager := patterns.NewPatternManager()
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   100,
	})
	value := "Server=db01;Database=app;Integrated Security=true;"
	findings, err := detector.DetectSecrets(value, "file://production.config")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range findings {
		if item.Type == "mssql_connection_string" {
			t.Fatalf("passwordless integrated-security connection was emitted: %+v", item)
		}
	}
}

func TestMSSQLNamedInstanceWithFQDNIsDetected(t *testing.T) {
	manager := patterns.NewPatternManager()
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   100,
	})
	value := `Server=db.internal\SQLEXPRESS;Database=app;UID=svc;PWD=A7kQ9mX2vR5tY8uP;`
	findings, err := detector.DetectSecrets(value, "file://production.config")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "mssql_connection_string", value)
}

func TestCredentialURIExamplesRemainRejected(t *testing.T) {
	manager := patterns.NewPatternManager()
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   100,
	})
	value := "postgresql://user:password@db.example.com/app"
	findings, err := detector.DetectSecrets("EXAMPLE_DATABASE_URL=\""+value+"\"", "file://docs/example.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range findings {
		if item.Type == "postgresql_connection_string" && item.Value == value {
			t.Fatalf("documentation credential URI was accepted: %+v", item)
		}
	}
}
