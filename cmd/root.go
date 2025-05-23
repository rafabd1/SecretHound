package cmd

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "secrethound [flags] [target]",
	Short: "Scan targets (URLs or local files/dirs) for secrets or URLs",
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
  secrethound --include-categories pii,web3 urls.txt
  secrethound ./path/to/project --scan-urls # URL Extraction Mode

Flag Categories:
  Input Sources:     -i, --input-file
  Output:            -o, --output | --raw
  Performance:       -c, --concurrency | -l, --rate-limit
  Networking:        -t, --timeout | -r, --retries | -H, --header | --insecure
  Pattern Control:   --include-categories | --exclude-categories | --scan-urls | --list-patterns
  General Behavior:  -v, --verbose | -n, --no-progress | -s, --silent
`,
	RunE: runScan,
	Args: func(cmd *cobra.Command, args []string) error {
		// --- List Patterns Check --- 
		lp, _ := cmd.Flags().GetBool("list-patterns")
		if lp {
			if len(args) != 0 { 
				return fmt.Errorf("accepts 0 arguments when --list-patterns is used, received %d", len(args))
			}
			return nil
		}

		// --- Input Source Check --- 
		inputFileUsed, _ := cmd.Flags().GetString("input-file")
		hasInputFile := inputFileUsed != ""

		if hasInputFile {
			return nil 
		}

		if len(args) != 1 {
			return fmt.Errorf("requires exactly one target argument (URL, file, or directory) if --input-file is not used, received %d", len(args))
		}

		return nil
	},
	DisableFlagsInUseLine: true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

// beforeCommand executes before any command runs
func beforeCommand() {  
    runtime.GC()
    
    time.Sleep(100 * time.Millisecond)
}

// Execute adds all child commands to the root command
func Execute() {
	originalPreRun := rootCmd.PreRun
	rootCmd.PreRun = func(cmd *cobra.Command, args []string) {
		beforeCommand()
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
	vip := viper.GetViper()

	// --- Persistent Flags (available to all commands, though we only have root effectively) ---
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging output")
	vip.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

	// --- Local Flags (specific to the root/scan command) ---

	// Group: Input Sources
	rootCmd.Flags().StringP("input-file", "i", "", "Input file containing URLs or paths (alternative to target argument)")
	vip.BindPFlag("input_file", rootCmd.Flags().Lookup("input-file"))

	// Group: Output
	rootCmd.Flags().StringP("output", "o", "", "Output file to save results (json or txt, default: stdout)")
	vip.BindPFlag("output", rootCmd.Flags().Lookup("output"))

	// Group: Output Format (Added Group)
	rootCmd.Flags().Bool("raw", false, "Output only raw secret values (affects file output only)")
	vip.BindPFlag("raw", rootCmd.Flags().Lookup("raw"))

	// Group: Performance
	rootCmd.Flags().IntP("concurrency", "c", 50, "Number of concurrent workers") // Default changed to 50 based on scan.go edits
	rootCmd.Flags().IntP("rate-limit", "l", 0, "Max requests per second per domain (0 for auto/unlimited)") // Moved from persistent
	vip.BindPFlag("concurrency", rootCmd.Flags().Lookup("concurrency"))
	vip.BindPFlag("rate_limit", rootCmd.Flags().Lookup("rate-limit"))

	// Group: Networking
	rootCmd.Flags().IntP("timeout", "t", 10, "HTTP request timeout in seconds")
	rootCmd.Flags().IntP("retries", "r", 2, "Maximum number of retries for HTTP requests") // Default changed to 2 based on scan.go edits
	rootCmd.Flags().StringSliceP("header", "H", []string{}, "Custom headers to add (e.g., \"Authorization: Bearer token\")")
	rootCmd.Flags().Bool("insecure", false, "Disable SSL/TLS certificate verification") // Moved from persistent
	vip.BindPFlag("timeout", rootCmd.Flags().Lookup("timeout"))
	vip.BindPFlag("retries", rootCmd.Flags().Lookup("retries"))
	vip.BindPFlag("headers", rootCmd.Flags().Lookup("header"))
	vip.BindPFlag("insecure", rootCmd.Flags().Lookup("insecure"))

	// Group: Pattern Control
	rootCmd.Flags().StringSlice("include-categories", []string{}, "Comma-separated list of pattern categories to include (e.g., aws,gcp)")
	rootCmd.Flags().StringSlice("exclude-categories", []string{}, "Comma-separated list of pattern categories to exclude (e.g., pii,generic)")
	rootCmd.Flags().Bool("scan-urls", false, "URL Extraction Mode: Scan ONLY for URL/Endpoint patterns (overrides category filters)")
	rootCmd.Flags().Bool("list-patterns", false, "List available pattern categories and patterns, then exit")
	vip.BindPFlag("include_categories", rootCmd.Flags().Lookup("include-categories"))
	vip.BindPFlag("exclude_categories", rootCmd.Flags().Lookup("exclude-categories"))
	vip.BindPFlag("scan_urls", rootCmd.Flags().Lookup("scan-urls"))
	vip.BindPFlag("list_patterns", rootCmd.Flags().Lookup("list-patterns"))

	// Group: Output Format (Adicionando a nova flag aqui)
	rootCmd.Flags().Bool("group-by-source", false, "Group secrets by source URL/file in the output")
	vip.BindPFlag("group_by_source", rootCmd.Flags().Lookup("group-by-source"))

	// Group: General Behavior
	rootCmd.Flags().BoolP("no-progress", "n", false, "Disable the progress bar display") // Added based on scan.go
	rootCmd.Flags().BoolP("silent", "s", false, "Silent mode (suppress progress bar and info logs)") // Kept, might conflict with no-progress? Review needed.
	vip.BindPFlag("no_progress", rootCmd.Flags().Lookup("no-progress"))
	vip.BindPFlag("silent", rootCmd.Flags().Lookup("silent"))

}

