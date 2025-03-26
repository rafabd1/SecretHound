package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	Use:   "scan [flags] [urls/files/directories...]",
	Short: "Scan files for secrets",
	Long: `Scan files for secrets using regex patterns.
You can provide URLs, local files, or directories as arguments, or use the -i flag to specify an input source.

The scanner works with:
- Remote files via URLs (any file type, not just JavaScript)
- Local files (text-based formats that can be read as plain text)
- Directories (all readable files in the directory will be scanned)
- Lists of URLs/files in a text file (one per line)`,
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

	// Process input sources to get list of URLs or files to scan
	inputs, err := collectInputSources(inputFile, args, logger)
	if err != nil {
		return err
	}

	if len(inputs) == 0 {
		return fmt.Errorf("no valid input sources found. Use -i flag or provide URLs/files as arguments")
	}

	// Separate remote URLs and local files for different processing
	remoteURLs, localFiles := categorizeInputs(inputs)

	// Log statistics about input sources
	logInputSummary(logger, remoteURLs, localFiles)

	// Process remote URLs
	if len(remoteURLs) > 0 {
		if err := processRemoteURLs(remoteURLs, logger, writer); err != nil {
			logger.Error("Error processing remote URLs: %v", err)
			// Continue with local files even if remote processing failed
		}
	}

	// Process local files
	if len(localFiles) > 0 {
		if err := processLocalFiles(localFiles, logger, writer); err != nil {
			logger.Error("Error processing local files: %v", err)
		}
	}

	return nil
}

// collectInputSources gathers all input sources from arguments and input file
func collectInputSources(inputFile string, args []string, logger *output.Logger) ([]string, error) {
	var inputs []string

	// First, collect from command line arguments
	if len(args) > 0 {
		inputs = append(inputs, args...)
		logger.Info("Added %d sources from command line arguments", len(args))
	}

	// Then, if input file is specified, read from it
	if inputFile != "" {
		// Use correct path handling for Windows
		inputPath := filepath.FromSlash(inputFile)
		
		// Check if input is a file containing URLs/paths or a directory
		fileInfo, err := os.Stat(inputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to access input file/directory '%s': %v", inputPath, err)
		}

		if fileInfo.IsDir() {
			// If it's a directory, collect all files in it
			dirFiles, err := collectFilesFromDirectory(inputPath, logger)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, dirFiles...)
			logger.Info("Added %d files from directory: %s", len(dirFiles), inputPath)
		} else {
			// Check if the file is a javascript file or a text file with a list of URLs
			if strings.HasSuffix(strings.ToLower(inputPath), ".js") || 
			   strings.HasSuffix(strings.ToLower(inputPath), ".jsx") ||
			   strings.HasSuffix(strings.ToLower(inputPath), ".ts") ||
			   strings.HasSuffix(strings.ToLower(inputPath), ".html") ||
			   strings.HasSuffix(strings.ToLower(inputPath), ".css") ||
			   strings.HasSuffix(strings.ToLower(inputPath), ".txt") ||
			   strings.HasSuffix(strings.ToLower(inputPath), ".json") {
				// It's a single file to scan
				inputs = append(inputs, inputPath)
				logger.Info("Added single file to scan: %s", inputPath)
			} else {
				// Assume it's a list file and try to read URLs from it
				content, err := os.ReadFile(inputPath)
				if err != nil {
					return nil, fmt.Errorf("failed to read input file: %v", err)
				}
				
				// Split by lines
				lines := strings.Split(string(content), "\n")
				urlCount := 0
				
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						inputs = append(inputs, line)
						urlCount++
					}
				}
				
				logger.Info("Added %d sources from list file: %s", urlCount, inputPath)
			}
		}
	}

	return inputs, nil
}

// collectFilesFromDirectory recursively collects all readable files from a directory
func collectFilesFromDirectory(dirPath string, logger *output.Logger) ([]string, error) {
	var files []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Warning("Error accessing path %s: %v", path, err)
			return nil // Continue walking even if we encounter an error
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip binary files and very large files
		if utils.IsBinaryFile(path) || info.Size() > 10*1024*1024 { // 10MB max
			logger.Debug("Skipping binary or large file: %s", path)
			return nil
		}

		// Only add text-based files that we can process
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".js" || ext == ".jsx" || ext == ".ts" ||
		   ext == ".html" || ext == ".css" || ext == ".json" ||
		   ext == ".txt" || ext == ".xml" || ext == ".yml" ||
		   ext == ".yaml" || ext == ".md" || ext == ".csv" ||
		   ext == ".config" || ext == ".ini" || ext == ".conf" ||
		   ext == "" /* no extension, might be a text file */ {
			files = append(files, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %v", dirPath, err)
	}

	return files, nil
}

// categorizeInputs separates inputs into remote URLs and local files
func categorizeInputs(inputs []string) ([]string, []string) {
	var remoteURLs, localFiles []string

	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
			// It's a remote URL
			remoteURLs = append(remoteURLs, input)
		} else {
			// Check if it's a file path on disk
			if _, err := os.Stat(input); err == nil {
				// It's a local file or directory that exists
				localFiles = append(localFiles, input)
			} else if utils.IsValidURL(input) {
				// It looks like a URL but doesn't have http/https prefix
				remoteURLs = append(remoteURLs, "https://"+input)
			} else {
				// Treat as a local file anyway - let the scanner handle errors
				localFiles = append(localFiles, input)
			}
		}
	}

	return remoteURLs, localFiles
}

// logInputSummary logs summary information about the inputs
func logInputSummary(logger *output.Logger, remoteURLs, localFiles []string) {
	fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
		time.Now().Format("15:04:05"),
		color.CyanString("[INFO]"),
		fmt.Sprintf("Found %d remote URLs to scan", len(remoteURLs)))

	fmt.Fprintf(os.Stderr, "[%s] %s %s\n",
		time.Now().Format("15:04:05"),
		color.CyanString("[INFO]"),
		fmt.Sprintf("Found %d local files to scan", len(localFiles)))
}

// processRemoteURLs processes remote URLs using the existing web scanning logic
func processRemoteURLs(urls []string, logger *output.Logger, writer *output.Writer) error {
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
		fmt.Sprintf("Processing %d valid remote URLs", len(validURLs)))

	// Create domain manager
	domainManager := networking.NewDomainManager()
	domainManager.GroupURLsByDomain(validURLs)

	// Create HTTP client
	client := networking.NewClient(timeout, maxRetries)

	// Create regex manager and load patterns
	regexManager := createAndInitRegexManager(logger)

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

// processLocalFiles processes local files using a direct file reading approach
func processLocalFiles(files []string, logger *output.Logger, writer *output.Writer) error {
	// Ensure there are files to process
	if len(files) == 0 {
		return nil // No local files to process
	}
	
	// Log that we're processing local files
	logger.Info("Starting to process %d local files", len(files))
	
	// Create regex manager and load patterns
	regexManager := createAndInitRegexManager(logger)
	
	// Create processor
	processor := core.NewProcessor(regexManager, logger)
	
	// Create local file scanner
	scanner := core.NewLocalScanner(processor, writer, logger)
	scanner.SetConcurrency(concurrency)
	
	// Start processing local files
	return scanner.ScanFiles(files)
}

// createAndInitRegexManager creates and initializes a RegexManager with patterns
func createAndInitRegexManager(logger *output.Logger) *core.RegexManager {
	regexManager := core.NewRegexManager()
	
	// Load regex patterns
	if regexFile != "" {
		err := regexManager.LoadPatternsFromFile(regexFile)
		if err != nil {
			if verbose {
				logger.Warning("Failed to load regex patterns from file: %v", err)
				logger.Info("Loading predefined patterns instead")
			}

			err = regexManager.LoadPredefinedPatterns()
			if err != nil {
				logger.Error("Failed to load predefined regex patterns: %v", err)
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

		err := regexManager.LoadPredefinedPatterns()
		if err != nil {
			logger.Error("Failed to load predefined regex patterns: %v", err)
		}
	}
	
	return regexManager
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file, directory, or URL list")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for the results")
	scanCmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "HTTP request timeout in seconds")
	scanCmd.Flags().IntVarP(&maxRetries, "retries", "r", 3, "maximum number of retries for HTTP requests")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "n", 10, "number of concurrent workers")
	scanCmd.Flags().IntVarP(&rateLimit, "rate-limit", "l", 0, "requests per second per domain (0 = auto)")
	scanCmd.Flags().StringVar(&regexFile, "regex-file", "", "file containing regex patterns (optional)")
}
