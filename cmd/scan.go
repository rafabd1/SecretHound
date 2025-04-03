package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rafabd1/SecretHound/config"
	"github.com/rafabd1/SecretHound/core"
	"github.com/rafabd1/SecretHound/networking"
	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
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

	timeColor := color.New(color.FgHiBlack).SprintfFunc()
	timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))

	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
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

	// Wait for processing to complete without a timeout
	<-done
	
	// Normal completion
	timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "%s %s %s\n", 
		timeStr,
		color.CyanString("[INFO]"), 
		"All processing completed successfully")

	logger.Flush()
	
	time.Sleep(500 * time.Millisecond)

	if writer != nil {
		secretCount := writer.GetCount()
		timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
		fmt.Fprintf(os.Stderr, "%s %s %s\n", 
			timeStr,
			color.GreenString("[SUCCESS]"), 
			fmt.Sprintf("Found a total of %d secrets", secretCount))
		
		timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
		fmt.Fprintf(os.Stderr, "%s %s %s\n", 
			timeStr,
			color.CyanString("[INFO]"), 
			fmt.Sprintf("Results saved to: %s", outputFile))
	}

	timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "\n%s %s %s\n", 
		timeStr,
		color.CyanString("[INFO]"), 
		"Scan completed. Exiting.")
	
	time.Sleep(200 * time.Millisecond)
	
	os.Exit(0)

	// Ao final do processamento, garantir que todos os logs foram concluídos
	if logger != nil {
		logger.Flush()
		// Pausa adicional para garantir ordem dos logs
		time.Sleep(200 * time.Millisecond)
	}

	return nil
}

// collectInputSources gathers all input sources from arguments and input file
func collectInputSources(inputFile string, args []string, logger *output.Logger) ([]string, error) {
    var inputs []string

    // First, collect from command line arguments
    if (len(args) > 0) {
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
            isURLList, contents, err := isFileURLList(inputPath)
            if err != nil {
                return nil, err
            }
            
            if isURLList {
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
	if len(localFiles) > 0 {
		timeColor := color.New(color.FgHiBlack).SprintfFunc()
		timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))
		
		fmt.Fprintf(os.Stderr, "%s %s %s\n",
			timeStr,
			color.CyanString("[INFO]"),
			fmt.Sprintf("Found %d local files to scan", len(localFiles)))
	}
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

	// Create domain manager
	domainManager := networking.NewDomainManager()
	domainManager.GroupURLsByDomain(validURLs)

	// Create HTTP client
	client := networking.NewClient(timeout, maxRetries)
	
	// Apply custom headers if provided
	if len(customHeader) > 0 {
		for _, header := range customHeader {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				client.SetRequestHeader(name, value)
				logger.Debug("Set custom header: %s: %s", name, value)
			} else {
				logger.Warning("Invalid header format (should be 'Name: Value'): %s", header)
			}
		}
	}
	
	// Apply global rate limit if set
	if rateLimit > 0 {
		client.SetGlobalRateLimit(rateLimit)
	}

	// Create regex manager and load patterns
	regexManager := createAndInitRegexManager(logger)

	// Print initial statistics - consolidated to avoid redundancy
	timeColor := color.New(color.FgHiBlack).SprintfFunc()
	timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))

	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("Processing %d URLs across %d domains with %d regex patterns (%d workers)",
			len(validURLs),
			domainManager.GetDomainCount(),
			regexManager.GetPatternCount(),
			concurrency))
			
	// Display timeout, retries, and rate limit info
	timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("HTTP config: %d second timeout | %d max retries | %d requests per domain", 
			timeout, maxRetries, client.GetRateLimit()))

	// Display custom headers info if provided (without showing values for security)
	if len(customHeader) > 0 {
		headerNames := make([]string, 0, len(customHeader))
		for _, header := range customHeader {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				headerNames = append(headerNames, strings.TrimSpace(parts[0]))
			}
		}
		
		if len(headerNames) > 0 {
			timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
			fmt.Fprintf(os.Stderr, "%s %s %s\n",
				timeStr,
				color.CyanString("[INFO]"),
				fmt.Sprintf("Using custom headers: %s", strings.Join(headerNames, ", ")))
		}
	}

	// Create processor
	processor := core.NewProcessor(regexManager, logger)

	// Create scheduler
	scheduler := core.NewScheduler(domainManager, client, processor, writer, logger)
	scheduler.SetConcurrency(concurrency)

	time.Sleep(100 * time.Millisecond)

	err := scheduler.Schedule(validURLs)
	
	schedulerStats := scheduler.GetStats()
	
	timeColor = color.New(color.FgHiBlack).SprintfFunc()
	
	// Calculate processing rate and duration
	duration := schedulerStats.EndTime.Sub(schedulerStats.StartTime)
	urlsPerSecond := float64(schedulerStats.ProcessedURLs) / duration.Seconds()
	
	// Display final statistics
	timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "%s %s %s\n", 
		timeStr,
		color.CyanString("[INFO]"), 
		fmt.Sprintf("Remote URL processing completed in %.2f seconds", duration.Seconds()))
	
	timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "%s %s %s\n", 
		timeStr,
		color.CyanString("[INFO]"), 
		fmt.Sprintf("Processed %d URLs (%.2f URLs/second)", schedulerStats.ProcessedURLs, urlsPerSecond))
	
	timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "%s %s %s\n", 
		timeStr,
		color.CyanString("[INFO]"), 
		fmt.Sprintf("Failed to process %d URLs", schedulerStats.FailedURLs))
	
	// Display rate limit and WAF information
	if schedulerStats.RateLimitHits > 0 || schedulerStats.WAFBlockHits > 0 {
		timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
		fmt.Fprintf(os.Stderr, "%s %s %s\n", 
			timeStr,
			color.CyanString("[INFO]"), 
			fmt.Sprintf("Encountered rate limiting %d times, WAF blocks %d times", 
				schedulerStats.RateLimitHits, schedulerStats.WAFBlockHits))
	}
	
	// Force a pause to ensure all messages are processed
	time.Sleep(100 * time.Millisecond)
	
	return err
}

// processLocalFiles processa arquivos locais usando o escaneador
func processLocalFiles(files []string, logger *output.Logger, writer *output.Writer) error {
	// Cria gerenciador de regex
	regexManager := core.NewRegexManager()
	
	// Carrega padrões padrão
	err := regexManager.LoadPredefinedPatterns()
	if err != nil {
		return fmt.Errorf("falha ao carregar padrões: %v", err)
	}
	
	// Força injeção de padrões padrão para arquivos locais
	regexManager.InjectDefaultPatternsDirectly()
	
	// Cria processador com gerenciador de regex
	processor := core.NewProcessor(regexManager, logger)

	// Configura escaneador local
	localScanner := core.NewLocalScanner(processor, writer, logger)
	
	// Configura concorrência
	localScanner.SetConcurrency(concurrency)
	
	// Escaneia arquivos
	return localScanner.ScanFiles(files)
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
				// Inicializar RegexManager com todos os padrões predefinidos
				regexManager.InjectDefaultPatternsDirectly()
            
				// Também tentar carregar via método normal para garantir
				err = regexManager.LoadPredefinedPatterns()
				if err != nil {
					logger.Warning("Failed to load predefined regex patterns: %v", err)
				}
			}
		} else {
			// Usar timeColor para garantir que os timestamps estejam na cor dim
			timeColor := color.New(color.FgHiBlack).SprintfFunc()
			timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))
			fmt.Fprintf(os.Stderr, "%s %s %s\n",
				timeStr,
				color.CyanString("[INFO]"),
				fmt.Sprintf("Loaded regex patterns from file: %s", regexFile))
		}
	} else {
        // Forçar carregamento direto para garantir todos os padrões
		regexManager.InjectDefaultPatternsDirectly()
        
        // Adicionalmente carregar pelo método normal
		err := regexManager.LoadPredefinedPatterns()
		if err != nil {
			logger.Warning("Failed to load predefined regex patterns: %v", err)
		}
	}
	
    // Verificar se todos os padrões foram carregados
    patternCount := regexManager.GetPatternCount()
    if patternCount < 50 {
        logger.Warning("Loaded only %d regex patterns. Expected at least 50 patterns.", patternCount)
        
        // Tentar novamente com injeção direta
        regexManager.InjectDefaultPatternsDirectly()
    }
    
	return regexManager
}

func init() {
	// We still add it as a subcommand for backward compatibility
	rootCmd.AddCommand(scanCmd)

	// No need to add flags here as they are already defined in the root command
}
