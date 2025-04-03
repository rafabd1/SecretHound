package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

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
	
	RegexFile    string `yaml:"regex_file"`
}

var Config = Configuration{
	Timeout:     30,
	MaxRetries:  3,
	Concurrency: 10,
	RateLimit:   0,
	Verbose:     false,
	RegexFile:   "",
}

/* 
   Loads configuration from a YAML file.
   Returns nil without error if file doesn't exist, using defaults instead.
*/
func LoadConfig(configFile string) error {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &Config)
}

func SaveConfig(configFile string) error {
	dir := filepath.Dir(configFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(Config)
	if err != nil {
		return err
	}

	return os.WriteFile(configFile, data, 0644)
}
