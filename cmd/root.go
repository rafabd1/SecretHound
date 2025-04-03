package cmd

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

var (
	inputFile    string
	outputFile   string
	verbose      bool
	timeout      int
	maxRetries   int
	concurrency  int
	rateLimit    int
	regexFile    string
	customHeader []string
	insecureSkipVerify bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:                   "secrethound [flags] [sources...]",
	Short:                 "SecretHound - Extract secrets from files and URLs",
	Long: `SecretHound is a CLI tool for extracting secrets from various sources:
- Remote URLs (not limited to JavaScript files)
- Local files (any text-based format)
- Directories (all text files in a directory)
- Lists of URLs or file paths

It utilizes multi-threading, regex patterns, and intelligent systems to handle
rate limiting and WAF blocks for remote resources.`,
	RunE:                  runScan,
	DisableFlagsInUseLine: true,
	Args:                  cobra.ArbitraryArgs,
	TraverseChildren:      true,
}

// beforeCommand executes before any command runs
func beforeCommand(cmd *cobra.Command, args []string) {
    fmt.Println("DEBUG: beforeCommand chamado, limpeza de estado global desativada para diagnóstico")
    
    runtime.GC()
    
    time.Sleep(100 * time.Millisecond)
}

// Execute adds all child commands to the root command
func Execute() {
    for _, cmd := range rootCmd.Commands() {
        originalPreRun := cmd.PreRun
        cmd.PreRun = func(cmd *cobra.Command, args []string) {
            beforeCommand(cmd, args)
            if originalPreRun != nil {
                originalPreRun(cmd, args)
            }
        }
    }
    
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func init() {
	// Temporarily disable config file support
	// rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./secrethound.yaml)")
	
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	
	rootCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file, directory, or URL list")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for the results")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "HTTP request timeout in seconds")
	rootCmd.Flags().IntVarP(&maxRetries, "retries", "r", 3, "maximum number of retries for HTTP requests")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "n", 10, "number of concurrent workers")
	rootCmd.Flags().IntVarP(&rateLimit, "rate-limit", "l", 0, "requests per second per domain (0 = auto)")
	// Temporarily disable regex file support
	// rootCmd.Flags().StringVar(&regexFile, "regex-file", "", "file containing regex patterns (optional)")
	rootCmd.Flags().StringArrayVarP(&customHeader, "header", "H", []string{}, "custom HTTP header (format: 'Name: Value') - can be used multiple times")
	
	rootCmd.PersistentFlags().BoolVar(&insecureSkipVerify, "insecure", false, "Disable SSL/TLS certificate verification")
	
	rootCmd.Flags().SetInterspersed(true)
}
