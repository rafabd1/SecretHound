package core

import "fmt"

// Secret represents a secret found during processing
type Secret struct {
    Type    string `json:"type"`      // Type of secret (based on regex pattern)
    Value   string `json:"value"`     // The value of the secret found
    URL     string `json:"url"`       // URL from where the secret was extracted
    Line    int    `json:"line"`      // Line where the secret was found (optional)
    Context string `json:"context"`   // Context around the secret
}

// String returns a string representation of the secret
func (s Secret) String() string {
    return fmt.Sprintf("[%s] %s (URL: %s, Line: %d, Context: %s)", 
        s.Type, s.Value, s.URL, s.Line, s.Context)
}