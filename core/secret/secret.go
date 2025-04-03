package secret

import (
	"fmt"
	"strings"
)

// Secret represents a detected secret
type Secret struct {
	Type        string // The type of the secret (e.g., "aws_key")
	Value       string // The actual secret value
	Context     string // Surrounding content for context
	URL         string // The URL or file where the secret was found
	Line        int    // Line number in the source
	Confidence  float64 // Confidence level (0.0-1.0)
	Description string  // Human-readable description
}

// SecretGroup represents a group of secrets of the same type from a source
type SecretGroup struct {
	Type    string   // The type of the secrets
	Secrets []Secret // The list of secrets
	Source  string   // The source (URL or file)
}

// SecretSummary provides a summary of found secrets
type SecretSummary struct {
	TotalCount      int
	TypeCounts      map[string]int
	SourceCounts    map[string]int
	HighConfidence  int
	MediumConfidence int
	LowConfidence   int
}

// NewSecret creates a new secret instance
func NewSecret(secretType, value, context, url string, line int) Secret {
	return Secret{
		Type:       secretType,
		Value:      value,
		Context:    context,
		URL:        url,
		Line:       line,
		Confidence: 0.8, // Default confidence
	}
}

// ExtractContext extracts surrounding context for a secret
func ExtractContext(content, match string, contextSize int) string {
	idx := strings.Index(content, match)
	if idx == -1 {
		return ""
	}

	// Extract content around the match
	contextStart := max(0, idx-contextSize)
	contextEnd := min(len(content), idx+len(match)+contextSize)
	
	return content[contextStart:contextEnd]
}

// GetSafeValue returns a safe version of the secret for display
func (s Secret) GetSafeValue(maskLength int) string {
	if len(s.Value) <= maskLength {
		return strings.Repeat("*", len(s.Value))
	}
	
	// Show first few and last few characters
	visible := min(3, len(s.Value)/4)
	return s.Value[:visible] + strings.Repeat("*", len(s.Value)-visible*2) + s.Value[len(s.Value)-visible:]
}

// String returns a string representation
func (s Secret) String() string {
	url := s.URL
	if s.Line > 0 {
		url = fmt.Sprintf("%s#L%d", url, s.Line)
	}
	
	return fmt.Sprintf("[%s] %s in %s", s.Type, s.GetSafeValue(4), url)
}

// GroupSecrets groups secrets by type
func GroupSecrets(secrets []Secret) map[string][]Secret {
	groups := make(map[string][]Secret)
	
	for _, secret := range secrets {
		groups[secret.Type] = append(groups[secret.Type], secret)
	}
	
	return groups
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
