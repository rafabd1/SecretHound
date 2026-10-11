package semantic

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestJuliaClassifierProtocol(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python is not available")
	}

	modelPath := t.TempDir()
	modulePath := filepath.Join(modelPath, "julia")
	if err := os.MkdirAll(modulePath, 0755); err != nil {
		t.Fatal(err)
	}
	fakeModule := `
class Engine:
    def logits(self, rows):
        tasks = {
            "person_name" if row["question"].startswith("Classify the semantic role")
            else "pii" if "detected as PII type" in row["question"]
            else "secret"
            for row in rows
        }
        if len(tasks) != 1:
            raise RuntimeError("mixed task prompts in one Julia batch")
        output = []
        for row in rows:
            if "MODEL_FP_CASE" in row["state"] and "GitHub Personal Access Token (github_token)" in row["question"] and row["question"].startswith("Which description matches"):
                output.append([0.0, 6.0])
            elif "192.0.2.10" in row["state"] and "Email Address (email_address)" not in row["question"] and row["question"].startswith("Which description matches") and row["options"][1].startswith("Unrelated text"):
                output.append([0.0, 6.0])
            elif "Érica d'Ávila" in row["state"]:
                output.append([6.0, 0.0])
            elif "detector_type: person_name" in row["state"]:
                output.append([0.0, 6.0])
            else:
                output.append([6.0, 0.0])
        return output

def load_model(*args, **kwargs):
    return Engine()
`
	if err := os.WriteFile(filepath.Join(modulePath, "__init__.py"), []byte(fakeModule), 0644); err != nil {
		t.Fatal(err)
	}

	classifier, err := NewJuliaClassifier(JuliaConfig{
		PythonExecutable: python,
		ModelPath:        modelPath,
		StartupTimeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer classifier.Close()

	predictions, err := classifier.Classify(context.Background(), []Candidate{
		{Type: "github_token", Description: "GitHub Personal Access Token", Value: "MODEL_FP_CASE", Source: "file:///repo/docs/example.md"},
		{Type: "generic_token", Description: "Generic Token", Value: "MODEL_FP_CASE", Source: "file:///repo/production/config.env"},
		{Type: "github_token", Description: "GitHub Personal Access Token", Value: "MODEL_FP_CASE", Source: "file:///repo/production/config.env"},
		{Type: "github_token", Description: "GitHub Personal Access Token", Value: "MODEL_FP_CASE", Source: "file:///repo/production/config.env", Context: "GITHUB_TOKEN=placeholder"},
		{Value: "REAL_CASE"},
		{Type: "ipv4_address", Category: "pii", Description: "IPv4 Address", Value: "192.0.2.10", Source: "file:///repo/production/config.env"},
		{Type: "email_address", Category: "pii", Description: "Email Address", Value: "person@company.test", Source: "file:///repo/production/config.env"},
		{Type: "person_name", Category: "pii", Description: "Person Name", Value: "Érica d'Ávila", Source: "file:///repo/tests/people.json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(predictions) != 8 {
		t.Fatalf("got %d predictions", len(predictions))
	}
	if predictions[0].Verdict != VerdictLikelyFalsePositive || predictions[1].Verdict != VerdictNotLikelyFalsePositive || predictions[2].Verdict != VerdictLikelyFalsePositive || predictions[3].Verdict != VerdictLikelyFalsePositive || predictions[4].Verdict != VerdictNotLikelyFalsePositive || predictions[5].Verdict != VerdictLikelyFalsePositive || predictions[6].Verdict != VerdictNotLikelyFalsePositive || predictions[7].Verdict != VerdictNotLikelyFalsePositive {
		t.Fatalf("unexpected predictions: %+v", predictions)
	}
}
