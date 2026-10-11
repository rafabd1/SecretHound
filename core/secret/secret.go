package secret

import "github.com/rafabd1/SecretHound/core/finding"

type Secret = finding.Finding

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
	return finding.New(secretType, value, context, url, line)
}

/*
Extracts text surrounding a match in content for providing context
*/
func ExtractContext(content, match string, contextSize int) string {
	return finding.ExtractContext(content, match, contextSize)
}

func ExtractContextAt(content string, start, end, contextSize int) string {
	return finding.ExtractContextAt(content, start, end, contextSize)
}

func ExtractContextAtWithMatchOffset(content string, start, end, contextSize int) (string, int) {
	return finding.ExtractContextAtWithMatchOffset(content, start, end, contextSize)
}

func GroupSecrets(secrets []Secret) map[string][]Secret {
	groups := make(map[string][]Secret)

	for _, secret := range secrets {
		groups[secret.Type] = append(groups[secret.Type], secret)
	}

	return groups
}
