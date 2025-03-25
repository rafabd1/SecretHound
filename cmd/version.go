package cmd

import (
	"fmt"
	"runtime"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	Version   = "0.1.0"
	BuildDate = "undefined"
	GitCommit = "undefined"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of SecretHound",
	Long:  `Display version information about SecretHound and the system it is running on.`,
	Run: func(cmd *cobra.Command, args []string) {
		bold := color.New(color.Bold).SprintFunc()
		cyan := color.New(color.FgCyan).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()
		
		fmt.Println(bold("SecretHound Version Information"))
		fmt.Printf("%s: %s\n", cyan("Version"), green(Version))
		fmt.Printf("%s: %s\n", cyan("Build Date"), green(BuildDate))
		fmt.Printf("%s: %s\n", cyan("Git Commit"), green(GitCommit))
		fmt.Printf("%s: %s\n", cyan("Go Version"), green(runtime.Version()))
		fmt.Printf("%s: %s/%s\n", cyan("Platform"), green(runtime.GOOS), green(runtime.GOARCH))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
