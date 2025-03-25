package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Configuration holds all configuration parameters for the application
type Configuration struct {
	// HTTP client configuration
	Timeout      int    `yaml:"timeout"`
	MaxRetries   int    `yaml:"max_retries"`
	Concurrency  int    `yaml:"concurrency"`
	RateLimit    int    `yaml:"rate_limit"`
	
	// Input/Output configuration
	InputFile    string `yaml:"input_file"`
	OutputFile   string `yaml:"output_file"`
	
	// Application behavior
	Verbose      bool   `yaml:"verbose"`
	
	// RegexFile specifies the file containing regex patterns
	RegexFile    string `yaml:"regex_file"`
}

// Default configuration values
var Config = Configuration{
	Timeout:     30,
	MaxRetries:  3,
	Concurrency: 10,
	RateLimit:   0, // 0 means auto-adjust
	Verbose:     false,
	RegexFile:   "regex.txt",
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(configFile string) error {
	// Check if the file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil // Return without error if file doesn't exist, using defaults
	}

	// Read the file - Atualizado para Go 1.24 (os.ReadFile em vez de ioutil.ReadFile)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	// Unmarshal the YAML data into the configuration
	return yaml.Unmarshal(data, &Config)
}

// SaveConfig saves the current configuration to a YAML file
func SaveConfig(configFile string) error {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(configFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Marshal the configuration to YAML
	data, err := yaml.Marshal(Config)
	if err != nil {
		return err
	}

	// Write the file - Atualizado para Go 1.24 (os.WriteFile em vez de ioutil.WriteFile)
	return os.WriteFile(configFile, data, 0644)
}
