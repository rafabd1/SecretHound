package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rafabd1/SecretHound/core"
	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/scanner"
	"github.com/rafabd1/SecretHound/networking"
	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Removed scanCmd definition
// var scanCmd = &cobra.Command{...}

// runScan is now called by rootCmd
func runScan(cmd *cobra.Command, args []string) error {
	// Use Viper to get config values bound from flags/config file
	vip := viper.GetViper()

	// Initialize Logger (using viper value)
	logger := output.NewLogger(vip.GetBool("verbose"))

	// --- List Patterns Handling ---
	if vip.GetBool("list_patterns") {
		printPatternList()
		return nil // Exit after listing
	}

	// --- Validate Category Flags & Determine Final Filters ---
	includeCats := vip.GetStringSlice("include_categories")
	excludeCats := vip.GetStringSlice("exclude_categories")
	scanUrlsFlag := vip.GetBool("scan_urls")

	var finalIncludeCategories []string
	var finalExcludeCategories []string // Need a separate variable for final excludes

	if scanUrlsFlag {
		// --scan-urls Mode: Use ONLY 'url' category, ignore others
		finalIncludeCategories = []string{"url"}
		finalExcludeCategories = []string{} // Ensure no excludes apply in this mode
		logger.Info("URL Extraction Mode active (--scan-urls). Scanning only for URL/Endpoint patterns.")

		// Warn if other category flags were used, as they are ignored
		if len(includeCats) > 0 || len(excludeCats) > 0 {
			logger.Warning("--scan-urls overrides --include-categories and --exclude-categories.")
		}
	} else {
		// Default Mode: Use include/exclude flags
		if len(includeCats) > 0 && len(excludeCats) > 0 {
			logger.Error("Error: --include-categories and --exclude-categories flags cannot be used together.")
			os.Exit(1)
		}
		finalIncludeCategories = includeCats
		finalExcludeCategories = excludeCats
	}

	// --- Centralized Pattern Loading ---
	pm := patterns.NewPatternManager()

	// Load patterns respecting final filters determined above
	err := pm.LoadPatterns(finalIncludeCategories, finalExcludeCategories) // Use final lists
	if err != nil {
		logger.Error("%s", fmt.Sprintf("Error loading patterns: %v", err))
		os.Exit(1)
	}
	// Pattern loading logging happens later

	// Create RegexManager and associate the configured PatternManager
	regexManager := core.NewRegexManager()
	regexManager.SetPatternManager(pm)

	// --- Get other config values from Viper (needed for logging) ---
	timeout := vip.GetInt("timeout")
	maxRetries := vip.GetInt("retries")
	rateLimit := vip.GetInt("rate_limit")
	concurrency := vip.GetInt("concurrency")
	inputFile := vip.GetString("input_file")
	outputFile := vip.GetString("output")

	// --- Log Initial Configuration Summary ---
	rateLimitStr := "auto"
	if rateLimit > 0 {
		rateLimitStr = fmt.Sprintf("%d req/s per domain", rateLimit)
	}
	// Update pattern info based on final include/exclude lists
	patternInfo := fmt.Sprintf("%d patterns loaded", pm.GetPatternCount())
	if scanUrlsFlag { // Special message for URL mode
	    patternInfo = fmt.Sprintf("%d URL patterns loaded", pm.GetPatternCount())
	} else if len(finalIncludeCategories) > 0 {
		patternInfo = fmt.Sprintf("%d patterns from categories: %v", pm.GetPatternCount(), finalIncludeCategories)
	} else if len(finalExcludeCategories) > 0 {
		patternInfo = fmt.Sprintf("%d patterns excluding categories: %v", pm.GetPatternCount(), finalExcludeCategories)
	}

	timeColorLog := color.New(color.FgHiBlack).SprintfFunc()
	timeStrLog := timeColorLog("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "%s %s HTTP config: %d sec timeout | %d max retries | %s\n",
		timeStrLog,
		color.CyanString("[INFO]"),
		timeout, maxRetries, rateLimitStr)
	fmt.Fprintf(os.Stderr, "%s %s Concurrency: %d workers | Patterns: %s\n",
		timeStrLog,
		color.CyanString("[INFO]"),
		concurrency, patternInfo)

	// Log output file status
	if outputFile != "" {
		fmt.Fprintf(os.Stderr, "%s %s Output: Results will be saved to %s\n",
			timeStrLog, // Reuse timestamp
			color.CyanString("[INFO]"),
			outputFile)
	} else {
		fmt.Fprintf(os.Stderr, "%s %s Output: Results will be printed to standard output\n",
			timeStrLog, // Reuse timestamp
			color.CyanString("[INFO]"))
	}

	var writer *output.Writer
	if outputFile != "" {
		// var err error // Already declared above for LoadPatterns
		writer, err = output.NewWriter(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer writer.Close()
	}

	// --- Input Collection ---
	// Pass logger to collectInputSources
	inputs, err := collectInputSources(inputFile, args, logger)
	if err != nil {
		return err
	}

	if len(inputs) == 0 {
		return fmt.Errorf("no valid input sources found. Use -i flag or provide URLs/files as arguments")
	}

	remoteURLs, localFiles := categorizeInputs(inputs)

	logInputSummary(logger, remoteURLs, localFiles)

	// --- Execute Scans (with corrected logic for passing patterns) ---
	var wg sync.WaitGroup

	if len(remoteURLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Create RegexManager & Processor specifically for remote scan
			regexManager := core.NewRegexManager()
			regexManager.SetPatternManager(pm) // Use the filtered pm
			processor := core.NewProcessor(regexManager, logger) // Create processor HERE

			// Pass the processor AND the pm (for logging count)
			if err := processRemoteURLs(remoteURLs, logger, writer, processor, pm); err != nil { // Pass processor AND pm
				logger.Error("%s", fmt.Sprintf("Error processing remote URLs: %v", err))
			}
		}()
	}

	if len(localFiles) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Pass only the PatternManager (pm) to local scan function
			if err := processLocalFiles(localFiles, logger, writer, pm); err != nil { // Pass only pm
				logger.Error("%s", fmt.Sprintf("Error processing local files: %v", err))
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	<-done

	logger.Flush()

	// Rest of the original runScan code for summary...
	time.Sleep(100 * time.Millisecond)
	if writer != nil {
		secretCount := writer.GetCount()
		timeStrLog = timeColorLog("[%s]", time.Now().Format("15:04:05"))
		fmt.Fprintf(os.Stderr, "%s %s %s\n",
			timeStrLog,
			color.GreenString("[SUCCESS]"),
			fmt.Sprintf("Found a total of %d secrets", secretCount))

		timeStrLog = timeColorLog("[%s]", time.Now().Format("15:04:05"))
		fmt.Fprintf(os.Stderr, "%s %s %s\n",
			timeStrLog,
			color.CyanString("[INFO]"),
			fmt.Sprintf("Results saved to: %s", outputFile))
	}

	timeStrLog = timeColorLog("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "\n%s %s %s\n",
		timeStrLog,
		color.CyanString("[INFO]"),
		"Scan completed. Exiting.")

	time.Sleep(200 * time.Millisecond)

	return nil
}

/* 
   Gathers all input sources from arguments and input file
*/
func collectInputSources(inputFile string, args []string, logger *output.Logger) ([]string, error) {
	var inputs []string

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
					// It's a file, check if it's a list of URLs/paths
					isList, contents, listErr := isFileURLList(arg)
					if listErr != nil {
						// Log error from isFileURLList but proceed assuming it's a single file
						logger.Warning("Error checking if '%s' is a list file: %v. Treating as single file.", arg, listErr)
						inputs = append(inputs, arg) // Add the file path itself
					} else if isList {
						listCount := 0
						for _, line := range contents {
							if line != "" && !strings.HasPrefix(line, "#") {
								inputs = append(inputs, line)
								listCount++
							}
						}
						logger.Info("Added %d sources from list file (argument): %s", listCount, arg)
					} else {
						// Not a list, add the file path itself
						inputs = append(inputs, arg)
						logger.Info("Added single file to scan (argument): %s", arg)
					}
				}
			}
		}
		// logger.Info("Processed %d sources from command line arguments", len(args)) // Logged inside loop now
	}

	if inputFile != "" {
		inputPath := filepath.FromSlash(inputFile)
		
		fileInfo, err := os.Stat(inputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to access input file/directory '%s': %v", inputPath, err)
		}

		if fileInfo.IsDir() {
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
				inputs = append(inputs, inputPath)
				logger.Info("Added single file to scan: %s", inputPath)
			}
		}
	}

	return inputs, nil
}

/* 
   Determines if a file contains a list of URLs/paths
*/
func isFileURLList(filePath string) (bool, []string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	
	var nonEmptyLines []string
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
			nonEmptyLines = append(nonEmptyLines, trimmedLine)
		}
	}
	
	if len(nonEmptyLines) == 0 {
		return false, nil, nil
	}
	
	ext := strings.ToLower(filepath.Ext(filePath))
	
	if isContentExtension(ext) {
		return false, nil, nil
	}
	
	if ext == ".txt" || ext == ".list" || ext == ".urls" {
		if ext == ".txt" {
			if len(nonEmptyLines) < 10 {
				if looksLikeCode(string(content)) {
					return false, nil, nil
				}
			}
			
			urlCount := 0
			for _, line := range nonEmptyLines[:min(10, len(nonEmptyLines))] {
				if looksLikeURLOrPath(line) {
					urlCount++
				}
			}
			
			return urlCount >= min(5, len(nonEmptyLines)/2), nonEmptyLines, nil
		}
		
		return true, nonEmptyLines, nil
	}
	
	if len(nonEmptyLines) > 5 {
		urlCount := 0
		for _, line := range nonEmptyLines[:min(5, len(nonEmptyLines))] {
			if looksLikeURLOrPath(line) {
				urlCount++
			}
		}
		
		return urlCount >= min(3, len(nonEmptyLines)/2), nonEmptyLines, nil
	}
	
	return false, nil, nil
}

/* 
   Checks if the file extension indicates content to scan directly
*/
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

/* 
   Checks if a string looks like a URL or file path
*/
func looksLikeURLOrPath(s string) bool {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return true
	}
	
	if strings.Contains(s, "/") || strings.Contains(s, "\\") {
		return true
	}
	
	if strings.Contains(s, ".") && !strings.ContainsAny(s, " \t\n\r") {
		parts := strings.Split(s, ".")
		if len(parts) >= 2 && len(parts[len(parts)-1]) >= 2 {
			return true
		}
	}
	
	return false
}

/* 
   Checks if content appears to be code
*/
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

/* 
   Recursively collects all readable files from a directory
*/
func collectFilesFromDirectory(dirPath string, logger *output.Logger) ([]string, error) {
	var files []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Warning("Error accessing path %s: %v", path, err)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if utils.IsBinaryFile(path) || info.Size() > 10*1024*1024 {
			logger.Debug("Skipping binary or large file: %s", path)
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".js" || ext == ".jsx" || ext == ".ts" ||
		   ext == ".html" || ext == ".css" || ext == ".json" ||
		   ext == ".txt" || ext == ".xml" || ext == ".yml" ||
		   ext == ".yaml" || ext == ".md" || ext == ".csv" ||
		   ext == ".config" || ext == ".ini" || ext == ".conf" ||
		   ext == "" {
			files = append(files, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %v", dirPath, err)
	}

	return files, nil
}

/* 
   Separates inputs into remote URLs and local files
*/
func categorizeInputs(inputs []string) ([]string, []string) {
	var remoteURLs, localFiles []string

	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
			remoteURLs = append(remoteURLs, input)
		} else {
			if _, err := os.Stat(input); err == nil {
				localFiles = append(localFiles, input)
			} else if utils.IsValidURL(input) {
				remoteURLs = append(remoteURLs, "https://"+input)
			} else {
				localFiles = append(localFiles, input)
			}
		}
	}

	return remoteURLs, localFiles
}

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

/* 
   Processes remote URLs using the web scanning logic
*/
func processRemoteURLs(urls []string, logger *output.Logger, writer *output.Writer, processor *core.Processor, pm *patterns.PatternManager) error {
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

	domainManager := networking.NewDomainManager()
	domainManager.GroupURLsByDomain(validURLs)

	// Get config from Viper
	vip := viper.GetViper()
	timeout := vip.GetInt("timeout")
	maxRetries := vip.GetInt("retries")
	insecureSkipVerify := vip.GetBool("insecure")
	customHeader := vip.GetStringSlice("headers")
	rateLimit := vip.GetInt("rate_limit")
	concurrency := vip.GetInt("concurrency")

	client := networking.NewClient(timeout, maxRetries)
	if insecureSkipVerify {
		client.SetInsecureSkipVerify(true)
		logger.Info("SSL/TLS certificate verification disabled")
	}
	// Set headers
	headersMap := make(map[string]string)
	for _, h := range customHeader {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headersMap[name] = value
			client.SetRequestHeader(name, value)
			logger.Debug("Set custom header: %s: %s", name, value)
		} else {
			logger.Warning("Invalid header format (should be 'Name: Value'): %s", h)
		}
	}
	if rateLimit > 0 {
		client.SetGlobalRateLimit(rateLimit)
	}

	// Processor is passed in, use it

	// Rest of the setup and logging...
	timeColor := color.New(color.FgHiBlack).SprintfFunc()
	timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))

	// Get pattern count directly from the passed PatternManager
	patternCount := pm.GetPatternCount()

	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("Processing %d URLs across %d domains with %d regex patterns (%d workers)",
			len(validURLs),
			domainManager.GetDomainCount(),
			patternCount, // Use count from pm
			concurrency))

	scheduler := core.NewScheduler(domainManager, client, processor, writer, logger)
	scheduler.SetConcurrency(concurrency)

	time.Sleep(100 * time.Millisecond)

	err := scheduler.Schedule(validURLs)

	schedulerStats := scheduler.GetStats()
	duration := schedulerStats.EndTime.Sub(schedulerStats.StartTime)
	urlsPerSecond := 0.0
	if duration.Seconds() > 0 {
		urlsPerSecond = float64(schedulerStats.ProcessedURLs) / duration.Seconds()
	}
	timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("Remote URL processing completed in %.2f seconds", duration.Seconds()))
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("Processed %d URLs (%.2f URLs/second)", schedulerStats.ProcessedURLs, urlsPerSecond))
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("Failed to process %d URLs", schedulerStats.FailedURLs))
	if schedulerStats.RateLimitHits > 0 || schedulerStats.WAFBlockHits > 0 {
		timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
		fmt.Fprintf(os.Stderr, "%s %s %s\n",
			timeStr,
			color.CyanString("[INFO]"),
			fmt.Sprintf("Encountered rate limiting %d times, WAF blocks %d times",
				schedulerStats.RateLimitHits, schedulerStats.WAFBlockHits))
	}
	time.Sleep(100 * time.Millisecond)
	return err
}

/* 
   Processes local files using the scanner
*/
func processLocalFiles(files []string, logger *output.Logger, writer *output.Writer, pm *patterns.PatternManager) error {
	// Get config from Viper
	vip := viper.GetViper()
	concurrency := vip.GetInt("concurrency")
	// excludeSecrets := vip.GetStringSlice("exclude_secrets") // No longer needed here

	// Processor is not needed here, LocalScanner uses pm directly

	// Use the core/scanner/local_scanner
	scannerCfg := scanner.LocalScannerConfig{
		Concurrency: concurrency,
		MaxFileSize: 10 * 1024 * 1024, // Or get from viper
	}
	// NewLocalScanner expects PatternManager, Writer, Logger, Config
	localScanner := scanner.NewLocalScanner(pm, writer, logger, scannerCfg)

	return localScanner.ScanFiles(files)
}

// printPatternList prints available patterns
func printPatternList() {
	fmt.Println("Available Pattern Categories and Patterns:")
	fmt.Println("===========================================")

	categorized := make(map[string][]struct{ Name string; Config patterns.PatternConfig })
	var categories []string
	categoryMap := make(map[string]bool)

	// Iterate over DefaultPatterns (defined in patterns package)
	for name, config := range patterns.DefaultPatterns.Patterns {
		if !config.Enabled {
			continue // Optionally skip disabled ones even in list
		}
		if config.Category == "" {
			config.Category = "uncategorized" // Assign default if missing
		}
		if !categoryMap[config.Category] {
			categories = append(categories, config.Category)
			categoryMap[config.Category] = true
		}
		// Store name along with config for sorting/printing
		categorized[config.Category] = append(categorized[config.Category], struct{ Name string; Config patterns.PatternConfig }{Name: name, Config: config})
	}

	// Sort categories alphabetically
	sort.Strings(categories)

	// Print grouped patterns
	for _, category := range categories {
		fmt.Printf("\n[%s]\n", strings.ToUpper(category))
		categoryPatterns := categorized[category]
		// Sort patterns within category alphabetically by name
		sort.Slice(categoryPatterns, func(i, j int) bool {
			return categoryPatterns[i].Name < categoryPatterns[j].Name
		})

		for _, p := range categoryPatterns {
			fmt.Printf("  - %-30s : %s\n", p.Name, p.Config.Description)
		}
	}
	fmt.Println("===========================================")
	fmt.Println("\nNote: Use category names with --include-categories or --exclude-categories flags.")
}

// Initialization function (called by Cobra/Viper)
func initScanCmd(cmd *cobra.Command) {
	vip := viper.GetViper()

	// --- Input Sources ---
	cmd.Flags().StringP("input", "i", "", "Input local file or directory path to scan")
	cmd.Flags().StringP("url-file", "f", "", "Input file containing URLs to scan (one per line)")
	// Note: URLs/files/dirs as direct args are handled by `args` in runScan
	vip.BindPFlag("input_file", cmd.Flags().Lookup("input"))
	vip.BindPFlag("url_file", cmd.Flags().Lookup("url-file"))

	// --- Output ---
	cmd.Flags().StringP("output", "o", "", "Output file to save results (default: stdout)")
	vip.BindPFlag("output", cmd.Flags().Lookup("output"))

	// --- Performance ---
	cmd.Flags().IntP("concurrency", "c", 50, "Number of concurrent workers")
	cmd.Flags().IntP("rate-limit", "l", 0, "Max requests per second per domain (0 for auto/unlimited)")
	vip.BindPFlag("concurrency", cmd.Flags().Lookup("concurrency"))
	vip.BindPFlag("rate_limit", cmd.Flags().Lookup("rate-limit"))

	// --- Networking ---
	cmd.Flags().IntP("timeout", "t", 10, "HTTP request timeout in seconds")
	cmd.Flags().IntP("retries", "r", 2, "Maximum number of retries for failed HTTP requests")
	cmd.Flags().StringP("proxy", "p", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	cmd.Flags().StringSliceP("header", "H", []string{}, "Custom headers to include in requests (e.g., 'Cookie: session=...')")
	cmd.Flags().Bool("insecure", false, "Disable TLS certificate verification")
	vip.BindPFlag("timeout", cmd.Flags().Lookup("timeout"))
	vip.BindPFlag("retries", cmd.Flags().Lookup("retries"))
	vip.BindPFlag("proxy", cmd.Flags().Lookup("proxy"))
	vip.BindPFlag("headers", cmd.Flags().Lookup("header"))
	vip.BindPFlag("insecure", cmd.Flags().Lookup("insecure"))

	// --- Pattern Control ---
	cmd.Flags().StringSlice("include-categories", []string{}, "Comma-separated list of pattern categories to include (e.g., aws,gcp)")
	cmd.Flags().StringSlice("exclude-categories", []string{}, "Comma-separated list of pattern categories to exclude (e.g., pii,generic)")
	cmd.Flags().Bool("scan-urls", false, "URL Extraction Mode: Scan ONLY for URL/Endpoint patterns (overrides category filters)") // Updated description
	cmd.Flags().Bool("list-patterns", false, "List available pattern categories and exit")
	vip.BindPFlag("include_categories", cmd.Flags().Lookup("include-categories"))
	vip.BindPFlag("exclude_categories", cmd.Flags().Lookup("exclude-categories"))
	vip.BindPFlag("scan_urls", cmd.Flags().Lookup("scan-urls"))
	vip.BindPFlag("list_patterns", cmd.Flags().Lookup("list-patterns"))

	// --- General Behavior ---
	cmd.Flags().BoolP("verbose", "v", false, "Enable verbose logging output")
	cmd.Flags().BoolP("no-progress", "n", false, "Disable the progress bar display")
	vip.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))
	vip.BindPFlag("no_progress", cmd.Flags().Lookup("no-progress"))
}

// Helper function defined locally within the package
func stringSliceContains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[strings.ToLower(s)] = struct{}{}
	}
	_, ok := set[strings.ToLower(item)]
	return ok
}

// Make sure initScanCmd is called appropriately, likely from root.go or where scanCmd is defined/added.
// Example (if scanCmd is defined in root.go):
// var scanCmd = &cobra.Command{ Use: "scan", ..., RunE: runScan }
// func init() { rootCmd.AddCommand(scanCmd); initScanCmd(scanCmd) }

