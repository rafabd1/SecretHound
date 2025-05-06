package cmd

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Re-introduce global vars needed for Cobra flag parsing
var (
	rateLimit          int
	insecureSkipVerify bool
	// verbose is also persistent, keep it if needed, or handle consistently
	verbose bool
)

// rootCmd now IS the scan command
var rootCmd = &cobra.Command{
	Use:   "secrethound [flags] [target]",
	Short: "Scan URLs or local files/directories for secrets",
	Long: `SecretHound is a CLI tool for extracting secrets from various sources:
- Remote URLs (not limited to JavaScript files)
- Local files (any text-based format)
- Directories (all text files in a directory)
- Lists of URLs or file paths

It utilizes multi-threading, regex patterns, and intelligent systems to handle
rate limiting and WAF blocks for remote resources.

Examples:
  secrethound urls.txt
  secrethound https://example.com/script.js
  secrethound ./path/to/file.js -o results.json
  secrethound --list-patterns
  secrethound --include-categories pii,web3 urls.txt`,
	RunE: runScan,
	Args: func(cmd *cobra.Command, args []string) error {
		lp, _ := cmd.Flags().GetBool("list-patterns")
		if lp {
			if len(args) != 0 {
				return fmt.Errorf("accepts 0 arguments when --list-patterns is used, received %d", len(args))
			}
			return nil
		}

		// Check if input file flag is used
		inputFileUsed, _ := cmd.Flags().GetString("input-file")
		hasInputFile := inputFileUsed != ""

		if hasInputFile {
			// If -i is used, 0 arguments are allowed
			if len(args) != 0 {
				return fmt.Errorf("accepts 0 arguments when --input-file flag is used, received %d", len(args))
			}
		} else {
			// If -i is NOT used, exactly 1 argument is required
			if len(args) != 1 {
				return fmt.Errorf("requires exactly one argument (target URL, file, or directory) if --input-file is not used, received %d", len(args))
			}
		}

		return nil
	},
	DisableFlagsInUseLine: true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

// beforeCommand executes before any command runs
func beforeCommand(cmd *cobra.Command, args []string) {  
    runtime.GC()
    
    time.Sleep(100 * time.Millisecond)
}

// Execute adds all child commands to the root command
func Execute() {
	originalPreRun := rootCmd.PreRun
	rootCmd.PreRun = func(cmd *cobra.Command, args []string) {
		beforeCommand(cmd, args)
		if originalPreRun != nil {
			originalPreRun(cmd, args)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Define ALL flags directly on rootCmd
	// Persistent Flags
	// Pass pointers to the corresponding global vars
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().IntVarP(&rateLimit, "rate-limit", "l", 0, "Requests per second per domain (default 0 = auto)")
	rootCmd.PersistentFlags().BoolVar(&insecureSkipVerify, "insecure", false, "Disable SSL/TLS certificate verification")

	// Local Flags (specific to the root/scan command)
	rootCmd.Flags().StringP("input-file", "i", "", "Input file containing URLs or paths (can also be passed as argument)")
	rootCmd.Flags().StringP("output", "o", "", "Output file to save results (json or txt)")
	rootCmd.Flags().IntP("timeout", "t", 10, "HTTP request timeout in seconds")
	rootCmd.Flags().IntP("retries", "r", 3, "Maximum number of retries for HTTP requests")
	rootCmd.Flags().IntP("concurrency", "n", 20, "Number of concurrent workers")
	rootCmd.Flags().StringSliceP("header", "H", []string{}, "Custom headers to add (e.g., \"Authorization: Bearer token\")")
	rootCmd.Flags().Bool("json", false, "Output results in JSON format (equivalent to -o file.json)")
	rootCmd.Flags().StringSliceP("exclude", "e", []string{}, "Regex patterns to exclude specific secrets")
	rootCmd.Flags().BoolP("silent", "s", false, "Silent mode (suppress progress bar and info logs)")
	rootCmd.Flags().StringSlice("include-categories", []string{}, "Comma-separated list of pattern categories to exclusively run (e.g., pii,web3)")
	rootCmd.Flags().StringSlice("exclude-categories", []string{}, "Comma-separated list of pattern categories to exclude (e.g., aws,gcp)")
	rootCmd.Flags().Bool("list-patterns", false, "List available pattern categories and patterns, then exit")

	vip := viper.GetViper()
	vip.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	vip.BindPFlag("rate_limit", rootCmd.PersistentFlags().Lookup("rate-limit"))
	vip.BindPFlag("insecure", rootCmd.PersistentFlags().Lookup("insecure"))

	vip.BindPFlag("input_file", rootCmd.Flags().Lookup("input-file"))
	vip.BindPFlag("output", rootCmd.Flags().Lookup("output"))
	vip.BindPFlag("timeout", rootCmd.Flags().Lookup("timeout"))
	vip.BindPFlag("retries", rootCmd.Flags().Lookup("retries"))
	vip.BindPFlag("concurrency", rootCmd.Flags().Lookup("concurrency"))
	vip.BindPFlag("headers", rootCmd.Flags().Lookup("header"))
	vip.BindPFlag("json_output", rootCmd.Flags().Lookup("json"))
	vip.BindPFlag("exclude_secrets", rootCmd.Flags().Lookup("exclude"))
	vip.BindPFlag("silent", rootCmd.Flags().Lookup("silent"))
	vip.BindPFlag("include_categories", rootCmd.Flags().Lookup("include-categories"))
	vip.BindPFlag("exclude_categories", rootCmd.Flags().Lookup("exclude-categories"))
	vip.BindPFlag("list_patterns", rootCmd.Flags().Lookup("list-patterns"))
}

// ---- Keep only Execute, init, beforeCommand ----
