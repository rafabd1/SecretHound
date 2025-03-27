package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	Hidden:  true, // Hide this command since it's now the default
	Use:     "scan [flags] [urls/files/directories...]",
	Short:   "Scan files for secrets",
	Long:    `Scan files for secrets using regex patterns.`, 
	RunE:    runScan,
	Aliases: []string{"s"},
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

	// Use a WaitGroup to track when processing is actually complete
	var wg sync.WaitGroup
    
	// Process remote URLs
	if len(remoteURLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := processRemoteURLs(remoteURLs, logger, writer); err != nil {
				logger.Error("Error processing remote URLs: %v", err)
			}
		}()
	}

	// Process local files
	if len(localFiles) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := processLocalFiles(localFiles, logger, writer); err != nil {
				logger.Error("Error processing local files: %v", err)
			}
		}()
	}

	// Create a channel that will be closed when the WaitGroup completes
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait with timeout to avoid hanging indefinitely
	select {
	case <-done:
		// Normal completion
		logger.Info("All processing completed successfully")
	case <-time.After(5 * time.Minute): // Maximum runtime - adjust as needed
		logger.Warning("Processing timed out after 5 minutes, forcing exit")
	}

	logger.Flush()
	
	time.Sleep(500 * time.Millisecond)

	fmt.Fprintln(os.Stderr, "\nScan completed. Exiting.")
	os.Exit(0)

	return nil
}

// collectInputSources gathers all input sources from arguments and input file
func collectInputSources(inputFile string, args []string, logger *output.Logger) ([]string, error) {
    var inputs []string

    // First, collect from command line arguments
    if len(args) > 0 {
        for _, arg := range args {
            arg = filepath.FromSlash(arg)
            
            if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
                inputs = append(inputs, arg)
            } else {
                fileInfo, err := os.Stat(arg)
                if err != nil {
                    logger.Warning("Failed to access '%s': %v", arg, err)
                    continue
                }

                if fileInfo.IsDir() {
                    dirFiles, err := collectFilesFromDirectory(arg, logger)
                    if err != nil {
                        logger.Warning("Error processing directory '%s': %v", arg, err)
                        continue
                    }
                    inputs = append(inputs, dirFiles...)
                } else {
                    inputs = append(inputs, arg)
                }
            }
        }
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
            // Determine if this is a file to scan or a list of URLs
            isURLList, contents, err := isFileURLList(inputPath)
            if err != nil {
                return nil, err
            }
            
            if isURLList {
                // It's a file containing URLs or paths
                urlCount := 0
                for _, line := range contents {
                    if line != "" && !strings.HasPrefix(line, "#") {
                        inputs = append(inputs, line)
                        urlCount++
                    }
                }
                logger.Info("Added %d sources from URL list file: %s", urlCount, inputPath)
            } else {
                // It's a single file to scan
                inputs = append(inputs, inputPath)
                logger.Info("Added single file to scan: %s", inputPath)
            }
        }
    }

    return inputs, nil
}

// isFileURLList determines if a file contains a list of URLs/paths
func isFileURLList(filePath string) (bool, []string, error) {
    // Read the file content
    content, err := os.ReadFile(filePath)
    if err != nil {
        return false, nil, fmt.Errorf("failed to read file: %v", err)
    }

    // Split by lines
    lines := strings.Split(string(content), "\n")
    
    // Extract non-empty, non-comment lines
    var nonEmptyLines []string
    for _, line := range lines {
        trimmedLine := strings.TrimSpace(line)
        if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
            nonEmptyLines = append(nonEmptyLines, trimmedLine)
        }
    }
    
    // If there are no non-empty lines, it's not a URL list
    if len(nonEmptyLines) == 0 {
        return false, nil, nil
    }
    
    // Get file extension
    ext := strings.ToLower(filepath.Ext(filePath))
    
    // First, check if it's a known content type (always scan directly)
    if isContentExtension(ext) {
        return false, nil, nil
    }
    
    // Next, check for list file extension (.txt, .list, .urls)
    if ext == ".txt" || ext == ".list" || ext == ".urls" {
        // For .txt files, we need to do additional checks
        if ext == ".txt" {
            // If it has few lines, check content to determine
            if len(nonEmptyLines) < 10 {
                // Check if content looks like code
                if looksLikeCode(string(content)) {
                    return false, nil, nil
                }
            }
            
            // Check if lines look like URLs/paths
            urlCount := 0
            for _, line := range nonEmptyLines[:min(10, len(nonEmptyLines))] {
                if looksLikeURLOrPath(line) {
                    urlCount++
                }
            }
            
            // If at least half of the first 10 lines look like URLs/paths, it's a URL list
            return urlCount >= min(5, len(nonEmptyLines)/2), nonEmptyLines, nil
        }
        
        // For .list and .urls, always treat as URL list
        return true, nonEmptyLines, nil
    }
    
    // For other files, check content to determine type
    if len(nonEmptyLines) > 5 {
        // Check if first 5 lines look like URLs or paths
        urlCount := 0
        for _, line := range nonEmptyLines[:min(5, len(nonEmptyLines))] {
            if looksLikeURLOrPath(line) {
                urlCount++
            }
        }
        
        // If most lines look like URLs/paths, it's a URL list
        return urlCount >= min(3, len(nonEmptyLines)/2), nonEmptyLines, nil
    }
    
    // Default to treating it as a single file
    return false, nil, nil
}

// isContentExtension checks if the file extension indicates content to scan directly
func isContentExtension(ext string) bool {
    contentExtensions := map[string]bool{
        ".js":   true,
        ".jsx":  true,
        ".ts":   true,
        ".tsx":  true,
        ".html": true,
        ".htm":  true,
        ".css":  true,
        ".json": true,
        ".xml":  true,
        ".yaml": true,
        ".yml":  true,
        ".md":   true,
        ".csv":  true,
        ".ini":  true,
        ".conf": true,
        ".config": true,
    }
    
    return contentExtensions[ext]
}

// looksLikeURLOrPath checks if a string looks like a URL or file path
func looksLikeURLOrPath(s string) bool {
    // Check for URL
    if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
        return true
    }
    
    // Check for file path patterns
    if strings.Contains(s, "/") || strings.Contains(s, "\\") {
        return true
    }
    
    // Check for domain-like pattern
    if strings.Contains(s, ".") && !strings.ContainsAny(s, " \t\n\r") {
        parts := strings.Split(s, ".")
        if len(parts) >= 2 && len(parts[len(parts)-1]) >= 2 {
            return true
        }
    }
    
    return false
}

// looksLikeCode checks if content appears to be code
func looksLikeCode(content string) bool {
    codePatterns := []string{
        "{", "}", "function", "var ", "let ", "const ", 
        "import ", "export ", "class ", "if ", "for ", 
        "while ", "switch ", "<html", "<div", "<script",
        "/*", "*/", "//", "#include", "#define", "package ",
    }
    
    for _, pattern := range codePatterns {
        if strings.Contains(content, pattern) {
            return true
        }
    }
    
    return false
}

// min returns the smaller of a and b
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
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
	if (regexFile != "") {
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
	// We still add it as a subcommand for backward compatibility
	rootCmd.AddCommand(scanCmd)

	// No need to add flags here as they are already defined in the root command
}
