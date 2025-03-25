package core

import (
	"github.com/secrethound/output"
)

// Processor is responsible for processing JS files and extracting secrets
type Processor struct {
	regexManager *RegexManager
	logger       *output.Logger
}

// NewProcessor creates a new processor instance
func NewProcessor(regexManager *RegexManager, logger *output.Logger) *Processor {
	return &Processor{
		regexManager: regexManager,
		logger:       logger,
	}
}

// ProcessJSContent processes JavaScript content and extracts secrets
func (p *Processor) ProcessJSContent(content string, url string) ([]Secret, error) {
	p.logger.Debug("Processing content from URL: %s", url)
	
	// Use the regex manager to find secrets in the content
	secrets, err := p.regexManager.FindSecrets(content, url)
	if err != nil {
		return nil, err
	}
	
	// Log each found secret
	for _, secret := range secrets {
		p.logger.SecretFound(secret.Type, secret.Value, secret.URL)
	}
	
	return secrets, nil
}

// Secret represents a discovered secret
type Secret struct {
	Type     string
	Value    string
	URL      string
	Line     int
	Context  string
}
