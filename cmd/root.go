package cmd

import (
	"fmt"
	"os"

	"github.com/secrethound/config"
	"github.com/secrethound/core"
	"github.com/secrethound/networking"
	"github.com/secrethound/output"
	"github.com/secrethound/utils"
	"github.com/spf13/cobra"
)

var (
	cfgFile     string
	inputFile   string
	outputFile  string
	verbose     bool
	timeout     int
	maxRetries  int
	concurrency int
	rateLimit   int
	regexFile   string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "secrethound",
	Short: "SecretHound - Extract secrets from JavaScript files",
	Long: `SecretHound is a CLI tool for extracting secrets from JavaScript files.
It utilizes multi-threading, regex patterns, and intelligent systems to handle
rate limiting and WAF blocks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Configure application
		config.Config.InputFile = inputFile
		config.Config.OutputFile = outputFile
		config.Config.Verbose = verbose
		config.Config.Timeout = timeout
		config.Config.MaxRetries = maxRetries
		config.Config.Concurrency = concurrency
		config.Config.RateLimit = rateLimit
		config.Config.RegexFile = regexFile

		// Initialize logger
		logger := output.NewLogger(verbose)
		logger.Info("Starting SecretHound v%s", Version)

		// Create writer for output
		var writer *output.Writer
		if outputFile != "" {
			var err error
			writer, err = output.NewWriter(outputFile)
			if err != nil {
				return fmt.Errorf("failed to create output file: %v", err)
			}
			defer writer.Close()
		}

		// Read input URLs
		var urls []string
		var err error
		if inputFile != "" {
			urls, err = utils.ReadLinesFromFile(inputFile)
			if err != nil {
				return fmt.Errorf("failed to read input file: %v", err)
			}
		} else if len(args) > 0 {
			urls = args
		} else {
			return fmt.Errorf("no input URLs provided. Use -i flag or provide URLs as arguments")
		}

		// Validate URLs
		validURLs := make([]string, 0, len(urls))
		for _, url := range urls {
			if utils.IsValidURL(url) {
				validURLs = append(validURLs, url)
			} else {
				logger.Warning("Invalid URL: %s", url)
			}
		}

		if len(validURLs) == 0 {
			return fmt.Errorf("no valid URLs found")
		}

		logger.Info("Found %d valid URLs to process", len(validURLs))

		// Create domain manager
		domainManager := networking.NewDomainManager()
		domainManager.GroupURLsByDomain(validURLs)

		// Create HTTP client
		client := networking.NewClient(timeout, maxRetries)

		// Create regex manager
		regexManager := core.NewRegexManager()
		err = regexManager.LoadPatternsFromFile(regexFile)
		if err != nil {
			return fmt.Errorf("failed to load regex patterns: %v", err)
		}

		// Create processor
		processor := core.NewProcessor(regexManager, logger)

		// Create scheduler
		scheduler := core.NewScheduler(domainManager, client, processor, writer, logger)

		// Start processing
		return scheduler.Schedule(validURLs)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Set up command line flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./secrethound.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	
	rootCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file with a list of URLs")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for the results")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "HTTP request timeout in seconds")
	rootCmd.Flags().IntVarP(&maxRetries, "retries", "r", 3, "maximum number of retries for HTTP requests")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "n", 10, "number of concurrent workers")
	rootCmd.Flags().IntVarP(&rateLimit, "rate-limit", "l", 0, "requests per second per domain (0 = auto)")
	rootCmd.Flags().StringVar(&regexFile, "regex-file", "regex.txt", "file containing regex patterns")
}
