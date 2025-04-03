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

var scanCmd = &cobra.Command{
	Hidden:  true,
	Use:     "scan [flags] [urls/files/directories...]",
	Short:   "Scan files for secrets",
	Long:    `Scan files for secrets using regex patterns.`, 
	RunE:    runScan,
	Aliases: []string{"s"},
}

func runScan(cmd *cobra.Command, args []string) error {
	config.Config.InputFile = inputFile
	config.Config.OutputFile = outputFile
	config.Config.Verbose = verbose
	config.Config.Timeout = timeout
	config.Config.MaxRetries = maxRetries
	config.Config.Concurrency = concurrency
	config.Config.RateLimit = rateLimit
	config.Config.RegexFile = regexFile

	logger := output.NewLogger(verbose)

	timeColor := color.New(color.FgHiBlack).SprintfFunc()
	timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))

	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		"Starting SecretHound scan")

	var writer *output.Writer
	if outputFile != "" {
		var err error
		writer, err = output.NewWriter(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer writer.Close()
	}

	inputs, err := collectInputSources(inputFile, args, logger)
	if err != nil {
		return err
	}

	if len(inputs) == 0 {
		return fmt.Errorf("no valid input sources found. Use -i flag or provide URLs/files as arguments")
	}

	remoteURLs, localFiles := categorizeInputs(inputs)

	logInputSummary(logger, remoteURLs, localFiles)

	var wg sync.WaitGroup
	
	if len(remoteURLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := processRemoteURLs(remoteURLs, logger, writer); err != nil {
				logger.Error("Error processing remote URLs: %v", err)
			}
		}()
	}

	if len(localFiles) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := processLocalFiles(localFiles, logger, writer); err != nil {
				logger.Error("Error processing local files: %v", err)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	<-done
	
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

	if logger != nil {
		logger.Flush()
		time.Sleep(200 * time.Millisecond)
	}

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
					inputs = append(inputs, arg)
				}
			}
		}
		logger.Info("Added %d sources from command line arguments", len(args))
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
func processRemoteURLs(urls []string, logger *output.Logger, writer *output.Writer) error {
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

	client := networking.NewClient(timeout, maxRetries)
	
	if insecureSkipVerify {
		client.SetInsecureSkipVerify(true)
		logger.Info("SSL/TLS certificate verification disabled")
	}
	
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
	
	if rateLimit > 0 {
		client.SetGlobalRateLimit(rateLimit)
	}

	regexManager := createAndInitRegexManager(logger)

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
			
	timeStr = timeColor("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("HTTP config: %d second timeout | %d max retries | %d requests per domain", 
			timeout, maxRetries, client.GetRateLimit()))

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

	processor := core.NewProcessor(regexManager, logger)

	scheduler := core.NewScheduler(domainManager, client, processor, writer, logger)
	scheduler.SetConcurrency(concurrency)

	time.Sleep(100 * time.Millisecond)

	err := scheduler.Schedule(validURLs)
	
	schedulerStats := scheduler.GetStats()
	
	timeColor = color.New(color.FgHiBlack).SprintfFunc()
	
	duration := schedulerStats.EndTime.Sub(schedulerStats.StartTime)
	urlsPerSecond := float64(schedulerStats.ProcessedURLs) / duration.Seconds()
	
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
func processLocalFiles(files []string, logger *output.Logger, writer *output.Writer) error {
	regexManager := core.NewRegexManager()
	
	err := regexManager.LoadPredefinedPatterns()
	if err != nil {
		return fmt.Errorf("failed to load patterns: %v", err)
	}
	
	regexManager.InjectDefaultPatternsDirectly()
	
	processor := core.NewProcessor(regexManager, logger)

	localScanner := core.NewLocalScanner(processor, writer, logger)
	
	localScanner.SetConcurrency(concurrency)
	
	return localScanner.ScanFiles(files)
}

/* 
   Creates and initializes a RegexManager with patterns
*/
func createAndInitRegexManager(logger *output.Logger) *core.RegexManager {
	regexManager := core.NewRegexManager()
	
	if (regexFile != "") {
		err := regexManager.LoadPatternsFromFile(regexFile)
		if err != nil {
			if verbose {
				logger.Warning("Failed to load regex patterns from file: %v", err)
				logger.Info("Loading predefined patterns instead")
				regexManager.InjectDefaultPatternsDirectly()
			
				err = regexManager.LoadPredefinedPatterns()
				if (err != nil) {
					logger.Warning("Failed to load predefined regex patterns: %v", err)
				}
			}
		} else {
			timeColor := color.New(color.FgHiBlack).SprintfFunc()
			timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))
			fmt.Fprintf(os.Stderr, "%s %s %s\n",
				timeStr,
				color.CyanString("[INFO]"),
				fmt.Sprintf("Loaded regex patterns from file: %s", regexFile))
		}
	} else {
		regexManager.InjectDefaultPatternsDirectly()
		
		err := regexManager.LoadPredefinedPatterns()
		if err != nil {
			logger.Warning("Failed to load predefined regex patterns: %v", err)
		}
	}
	
	patternCount := regexManager.GetPatternCount()
	if patternCount < 50 {
		logger.Warning("Loaded only %d regex patterns. Expected at least 50 patterns.", patternCount)
		
		regexManager.InjectDefaultPatternsDirectly()
	}
	
	return regexManager
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
