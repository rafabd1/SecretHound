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

func runScan(cmd *cobra.Command, args []string) error {
	vip := viper.GetViper()
	logger := output.NewLogger(vip.GetBool("verbose"), vip.GetBool("silent"))
	silentMode := vip.GetBool("silent")
	rawMode := vip.GetBool("raw")

	timeColorLog := color.New(color.FgHiBlack).SprintfFunc()

	if !silentMode {
		printHeader()
	}

	// --- List Patterns Handling ---
	if vip.GetBool("list_patterns") {
		printPatternList()
		return nil
	}

	// --- Validate Category Flags & Determine Final Filters ---
	includeCats := vip.GetStringSlice("include_categories")
	excludeCats := vip.GetStringSlice("exclude_categories")
	scanUrlsFlag := vip.GetBool("scan_urls")

	var finalIncludeCategories []string
	var finalExcludeCategories []string 

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
	err := pm.LoadPatterns(finalIncludeCategories, finalExcludeCategories) 
	if err != nil {
		logger.Error("%s", fmt.Sprintf("Error loading patterns: %v", err))
		os.Exit(1)
	}

	regexManager := core.NewRegexManager()
	regexManager.SetPatternManager(pm)

	timeout := vip.GetInt("timeout")
	maxRetries := vip.GetInt("retries")
	rateLimit := vip.GetInt("rate_limit")
	concurrency := vip.GetInt("concurrency")
	inputFile := vip.GetString("input_file")
	outputFile := vip.GetString("output")

	// --- Log Initial Configuration Summary (Conditionally) ---
	if !silentMode {
		rateLimitStr := "auto"
		if rateLimit > 0 {
			rateLimitStr = fmt.Sprintf("%d req/s per domain", rateLimit)
		}

		// Build HTTP config log message
		httpConfigLog := fmt.Sprintf("HTTP config: %d sec timeout | %d max retries | %s", timeout, maxRetries, rateLimitStr)
		netHeaders := vip.GetStringSlice("headers")
		if len(netHeaders) > 0 {
			if len(netHeaders) == 1 {
				httpConfigLog += fmt.Sprintf(" | Custom Header: %s", netHeaders[0])
			} else {
				httpConfigLog += fmt.Sprintf(" | Custom Headers: %d configured", len(netHeaders))
			}
		}

		// Update pattern info based on final include/exclude lists
		patternInfo := fmt.Sprintf("%d patterns loaded", pm.GetPatternCount())
		if scanUrlsFlag { 
			patternInfo = fmt.Sprintf("%d URL patterns loaded", pm.GetPatternCount())
		} else if len(finalIncludeCategories) > 0 {
			patternInfo = fmt.Sprintf("%d patterns from categories: %v", pm.GetPatternCount(), finalIncludeCategories)
		} else if len(finalExcludeCategories) > 0 {
			patternInfo = fmt.Sprintf("%d patterns excluding categories: %v", pm.GetPatternCount(), finalExcludeCategories)
		}

		timeStrLog := timeColorLog("[%s]", time.Now().Format("15:04:05"))
		fmt.Fprintf(os.Stderr, "%s %s %s\n",
			timeStrLog,
			color.CyanString("[INFO]"),
			httpConfigLog) 
		fmt.Fprintf(os.Stderr, "%s %s Concurrency: %d workers | Patterns: %s\n",
			timeStrLog,
			color.CyanString("[INFO]"),
			concurrency, patternInfo)

		if outputFile != "" {
			fmt.Fprintf(os.Stderr, "%s %s Output: Results will be saved to %s\n",
				timeStrLog,
		color.CyanString("[INFO]"),
				outputFile)
		} else {
			fmt.Fprintf(os.Stderr, "%s %s Output: Results will be printed to standard output\n",
				timeStrLog, 
				color.CyanString("[INFO]"))
		}
		fmt.Fprintln(os.Stderr)
	}

	var writer *output.Writer
	if outputFile != "" {
		var err error
		writer, err = output.NewWriter(outputFile, rawMode)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer writer.Close()
	} else {
		writer = nil
	}

	// --- Input Collection ---
	inputs, err := collectInputSources(inputFile, args, logger)
	if err != nil {
		return err
	}

	if len(inputs) == 0 {
		return fmt.Errorf("no valid input sources found. Use -i flag or provide URLs/files as arguments")
	}

	remoteURLs, localFiles := categorizeInputs(inputs)

	logInputSummary(logger, remoteURLs, localFiles)

	// --- Prepare Networking Components (if needed) ---
	var domainManager *networking.DomainManager
	var client *networking.Client
	if len(remoteURLs) > 0 {
		domainManager = networking.NewDomainManager()
		domainManager.GroupURLsByDomain(remoteURLs)

		// Get networking config directly from viper
		netTimeoutSeconds := vip.GetInt("timeout")
		netRetries := vip.GetInt("retries")
		netInsecure := vip.GetBool("insecure")
		netHeaders := vip.GetStringSlice("header")
		netRateLimit := vip.GetInt("rate_limit")

		// Pass timeout as int to NewClient
		client = networking.NewClient(netTimeoutSeconds, netRetries)
		if netInsecure {
			client.SetInsecureSkipVerify(true)
			logger.Info("SSL/TLS certificate verification disabled")
		}
		// Set headers
		for _, h := range netHeaders {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				client.SetRequestHeader(name, value)
				logger.Debug("Set custom header: %s: %s", name, value)
			} else {
				logger.Warning("Invalid header format (should be 'Name: Value'): %s", h)
			}
		}
		if netRateLimit > 0 {
			client.SetGlobalRateLimit(netRateLimit)
		}

		// Log domain distribution info HERE, after grouping and only if not silent
		if !silentMode {
		    timeStrLog := timeColorLog("[%s]", time.Now().Format("15:04:05"))
		    fmt.Fprintf(os.Stderr, "%s %s Processing %d URLs distributed across %d domains\n",
		        timeStrLog, color.CyanString("[INFO]"), len(remoteURLs), domainManager.GetDomainCount())
            fmt.Fprintln(os.Stderr)
		}
	}

	// --- Execute Scans (with corrected logic for passing patterns) ---
	var wg sync.WaitGroup
	var totalSecretsFound int32 
	var finalErr error
	var mu sync.Mutex // Mutex to protect totalSecretsFound and finalErr

	scanConcurrency := vip.GetInt("concurrency")
	
	if len(remoteURLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Create RegexManager & Processor specifically for remote scan
			regexManager := core.NewRegexManager()
			regexManager.SetPatternManager(pm) 
			processor := core.NewProcessor(regexManager, logger) 

			scheduler, err := core.NewScheduler(domainManager, client, processor, writer, logger, scanConcurrency, vip.GetBool("no_progress"), silentMode)
			if err != nil {
				logger.Error("Failed to create URL scheduler: %v", err)
				mu.Lock()
				if finalErr == nil { finalErr = err } 
				mu.Unlock()
				return
			}
			
			if err := scheduler.Schedule(remoteURLs); err != nil {
				logger.Error("Error processing remote URLs: %v", err)
				mu.Lock()
				if finalErr == nil { finalErr = err }
				mu.Unlock()
			}
			stats := scheduler.GetStats()
			mu.Lock()
			totalSecretsFound += int32(stats.TotalSecrets) 
			mu.Unlock()
		}()
	}

	if len(localFiles) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			secrets, err := processLocalFiles(localFiles, logger, writer, pm, scanConcurrency, vip.GetBool("no_progress"), silentMode) 
			if err != nil {
				logger.Error("Error processing local files: %v", err)
				mu.Lock()
				if finalErr == nil { finalErr = err }
				mu.Unlock()
			}
			mu.Lock()
			totalSecretsFound += int32(secrets)
			mu.Unlock()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	<-done

	logger.Flush()
	
	// --- Summary Logging (Conditionally) ---
	time.Sleep(100 * time.Millisecond)

	if !silentMode { 
		if outputFile != "" { 
			logger.Success("Found a total of %d secrets", totalSecretsFound)
			
			timeStrLog := timeColorLog("[%s]", time.Now().Format("15:04:05"))
		fmt.Fprintf(os.Stderr, "%s %s %s\n", 
			    timeStrLog, 
			color.CyanString("[INFO]"), 
			fmt.Sprintf("Results saved to: %s", outputFile))
		} else {
			logger.Success("Found a total of %d secrets", totalSecretsFound)
	}

		timeStrLog := timeColorLog("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "\n%s %s %s\n", 
			timeStrLog,
		color.CyanString("[INFO]"), 
		"Scan completed. Exiting.")
		time.Sleep(200 * time.Millisecond)
	}

	return finalErr
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
					isList, contents, listErr := isFileURLList(arg)
					if listErr != nil {
						// Log error from isFileURLList but proceed assuming it's a single file
						logger.Warning("Error checking if '%s' is a list file: %v. Treating as single file.", arg, listErr)
						inputs = append(inputs, arg) 
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
   Processes local files using the scanner
   Signature updated to accept silent bool
*/
func processLocalFiles(files []string, logger *output.Logger, writer *output.Writer, pm *patterns.PatternManager, concurrency int, noProgress bool, silent bool) (int, error) {
	scannerCfg := scanner.LocalScannerConfig{
		Concurrency: concurrency,
		MaxFileSize: 10 * 1024 * 1024,
		NoProgress:  noProgress,
		Silent:      silent,
	}

	localScanner := scanner.NewLocalScanner(pm, writer, logger, scannerCfg)

	stats, scanErr := localScanner.ScanFiles(files)

	// Log final stats from the scanner
	duration := stats.EndTime.Sub(stats.StartTime)
	filesPerSecond := 0.0
	if duration.Seconds() > 0 {
		filesPerSecond = float64(stats.ProcessedFiles) / duration.Seconds()
	}
	logger.Info("Local file processing completed in %.2f seconds", duration.Seconds())
	logger.Info("Processed %d files (%.2f files/second)", stats.ProcessedFiles, filesPerSecond)
	logger.Info("Skipped %d files, failed to process %d files", stats.SkippedFiles, stats.FailedFiles)

	return stats.TotalSecrets, scanErr
}

// printPatternList prints available patterns
func printPatternList() {
	fmt.Println("Available Pattern Categories and Patterns:")
	fmt.Println("===========================================")

	categorized := make(map[string][]struct{ Name string; Config patterns.PatternConfig })
	var categories []string
	categoryMap := make(map[string]bool)

	for name, config := range patterns.DefaultPatterns.Patterns {
		if !config.Enabled {
			continue 
		}
		if config.Category == "" {
			config.Category = "uncategorized" 
		}
		if !categoryMap[config.Category] {
			categories = append(categories, config.Category)
			categoryMap[config.Category] = true
		}
		categorized[config.Category] = append(categorized[config.Category], struct{ Name string; Config patterns.PatternConfig }{Name: name, Config: config})
	}

	sort.Strings(categories)

	for _, category := range categories {
		fmt.Printf("\n[%s]\n", strings.ToUpper(category))
		categoryPatterns := categorized[category]
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

// Helper function to print the header
func printHeader() {
	// ANSI Shadow font from patorjk.com or similar
	// Add padding spaces before v%s for approximate right alignment
	// Adjust the number of spaces as needed for better visual alignment
	header := fmt.Sprintf(`
   _____                   __  __  __                      __
  / ___/___  _____________/ /_/ / / /___  __  ______  ____/ /
  \__ \/ _ \/ ___/ ___/ __/ __/ /_/ / __ \/ / / / __ \/ __  /
 ___/ /  __/ /__/ /  / /_/ /_/ __  / /_/ / /_/ / / / / /_/ /
/____/\___/\___/_/   \__\/\__/_/ /_/\____/\__,_/_/ /_/\__,_/   v%s
`, Version)
	
	authorLine := `
Secrets Finder | Created by github.com/rafabd1
`
	// Print header (ASCII + Version)
	fmt.Fprint(os.Stderr, color.CyanString(header))
	// Print author line
	fmt.Fprint(os.Stderr, color.CyanString(authorLine))
	// Print an extra newline for spacing before logs
	fmt.Fprintln(os.Stderr) 
}

