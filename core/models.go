package core

import "fmt"

// Secret representa um segredo encontrado durante o processamento
type Secret struct {
    Type    string `json:"type"`      // Tipo de segredo (baseado no padrão regex)
    Value   string `json:"value"`     // O valor do segredo encontrado
    URL     string `json:"url"`       // URL de onde o segredo foi extraído
    Line    int    `json:"line"`      // Linha onde o segredo foi encontrado (opcional)
    Context string `json:"context"`   // Contexto ao redor do segredo
}

// String returns a string representation of the secret
func (s Secret) String() string {
    return fmt.Sprintf("[%s] %s (URL: %s, Line: %d, Context: %s)", 
        s.Type, s.Value, s.URL, s.Line, s.Context)
}