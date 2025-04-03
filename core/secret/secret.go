package secret

import (
	"fmt"
	"strings"
)

type Secret struct {
	Type        string
	Value       string
	Context     string
	URL         string
	Line        int
	Confidence  float64
	Description string
}

type SecretGroup struct {
	Type    string
	Secrets []Secret
	Source  string
}

type SecretSummary struct {
	TotalCount       int
	TypeCounts       map[string]int
	SourceCounts     map[string]int
	HighConfidence   int
	MediumConfidence int
	LowConfidence    int
}

func NewSecret(secretType, value, context, url string, line int) Secret {
	return Secret{
		Type:       secretType,
		Value:      value,
		Context:    context,
		URL:        url,
		Line:       line,
		Confidence: 0.8,
	}
}

/* 
   Extracts text surrounding a match in content for providing context 
*/
func ExtractContext(content, match string, contextSize int) string {
	idx := strings.Index(content, match)
	if idx == -1 {
		return ""
	}

	contextStart := max(0, idx-contextSize)
	contextEnd := min(len(content), idx+len(match)+contextSize)
	
	return content[contextStart:contextEnd]
}

/* 
   Returns a partially masked version of the secret value for safe display 
*/
func (s Secret) GetSafeValue(maskLength int) string {
	if len(s.Value) <= maskLength {
		return strings.Repeat("*", len(s.Value))
	}
	
	visible := min(3, len(s.Value)/4)
	return s.Value[:visible] + strings.Repeat("*", len(s.Value)-visible*2) + s.Value[len(s.Value)-visible:]
}

func (s Secret) String() string {
	url := s.URL
	if s.Line > 0 {
		url = fmt.Sprintf("%s#L%d", url, s.Line)
	}
	
	return fmt.Sprintf("[%s] %s in %s", s.Type, s.GetSafeValue(4), url)
}

func GroupSecrets(secrets []Secret) map[string][]Secret {
	groups := make(map[string][]Secret)
	
	for _, secret := range secrets {
		groups[secret.Type] = append(groups[secret.Type], secret)
	}
	
	return groups
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
