package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/secrethound/config"
	"github.com/secrethound/core"
	"github.com/secrethound/networking"
	"github.com/secrethound/output"
	"github.com/secrethound/utils"
	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [flags] [urls...]",
	Short: "Scan JavaScript files for secrets",
	Long: `Scan JavaScript files for secrets using regex patterns.
You can provide URLs as arguments or use the -i flag to specify a file containing URLs.`,
	RunE: runScan,
}

// runScan executes the scan command
func runScan(cmd *cobra.Command, args []string) error {
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

	// Força exibir a mensagem inicial independente do modo verbose
	fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
		time.Now().Format("15:04:05"),
		color.CyanString("[INFO]"),
		"Starting SecretHound scan")

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
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
			time.Now().Format("15:04:05"),
			color.CyanString("[INFO]"),
			fmt.Sprintf("Reading URLs from file: %s", inputFile))

		urls, err = utils.ReadLinesFromFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}
	} else if len(args) > 0 {
		urls = args
	} else {
		return fmt.Errorf("no input URLs provided. Use -i flag or provide URLs as arguments")
	}

	// Validate URLs and sanitize them
	validURLs := make([]string, 0, len(urls))
	for _, url := range urls {
		sanitizedURL := utils.SanitizeURL(url)
		if utils.IsValidURL(sanitizedURL) {
			validURLs = append(validURLs, sanitizedURL)
		} else {
			logger.Warning("Invalid URL: %s", url)
		}
	}

	if len(validURLs) == 0 {
		return fmt.Errorf("no valid URLs found")
	}

	fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
		time.Now().Format("15:04:05"),
		color.CyanString("[INFO]"),
		fmt.Sprintf("Found %d valid URLs to process", len(validURLs)))

	// Create domain manager
	domainManager := networking.NewDomainManager()
	domainManager.GroupURLsByDomain(validURLs)

	// Create HTTP client
	client := networking.NewClient(timeout, maxRetries)

	// Create regex manager
	regexManager := core.NewRegexManager()

	// Load regex patterns
	if regexFile != "" {
		err = regexManager.LoadPatternsFromFile(regexFile)
		if err != nil {
			if verbose {
				logger.Warning("Failed to load regex patterns from file: %v", err)
				logger.Info("Loading predefined patterns instead")
			}

			err = regexManager.LoadPredefinedPatterns()
			if err != nil {
				return fmt.Errorf("failed to load predefined regex patterns: %v", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
				time.Now().Format("15:04:05"),
				color.CyanString("[INFO]"),
				fmt.Sprintf("Loaded regex patterns from file: %s", regexFile))
		}
	} else {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
			time.Now().Format("15:04:05"),
			color.CyanString("[INFO]"),
			"Using built-in regex patterns")

		err = regexManager.LoadPredefinedPatterns()
		if err != nil {
			return fmt.Errorf("failed to load predefined regex patterns: %v", err)
		}
	}

	// Print initial statistics
	patternCount := regexManager.GetPatternCount()
	domainCount := domainManager.GetDomainCount()

	fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
		time.Now().Format("15:04:05"),
		color.CyanString("[INFO]"),
		fmt.Sprintf("Using %d regex patterns to search for secrets", patternCount))

	fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
		time.Now().Format("15:04:05"),
		color.CyanString("[INFO]"),
		fmt.Sprintf("URLs are distributed across %d domains", domainCount))

	fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
		time.Now().Format("15:04:05"),
		color.CyanString("[INFO]"),
		fmt.Sprintf("Running with %d concurrent workers", concurrency))

	if outputFile != "" {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
			time.Now().Format("15:04:05"),
			color.CyanString("[INFO]"),
			fmt.Sprintf("Results will be saved to: %s", outputFile))
	}

	// Create processor
	processor := core.NewProcessor(regexManager, logger)

	// Create scheduler
	scheduler := core.NewScheduler(domainManager, client, processor, writer, logger)
	scheduler.SetConcurrency(concurrency)

	// Inserir pequena pausa para garantir que as estatísticas sejam exibidas
	time.Sleep(100 * time.Millisecond)

	// Start processing
	return scheduler.Schedule(validURLs)
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file with a list of URLs")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for the results")
	scanCmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "HTTP request timeout in seconds")
	scanCmd.Flags().IntVarP(&maxRetries, "retries", "r", 3, "maximum number of retries for HTTP requests")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "n", 10, "number of concurrent workers")
	scanCmd.Flags().IntVarP(&rateLimit, "rate-limit", "l", 0, "requests per second per domain (0 = auto)")
	scanCmd.Flags().StringVar(&regexFile, "regex-file", "", "file containing regex patterns (optional)")
}
