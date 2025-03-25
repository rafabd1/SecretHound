package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/secrethound/cmd"
)

func main() {
	// Set GOMAXPROCS to use all available cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Print banner
	printBanner()

	// Execute the root command
	cmd.Execute()
}

// printBanner prints the application banner
func printBanner() {
	banner := `
   _____                   __  __  __                      __
  / ___/___  _____________/ /_/ / / /___  __  ______  ____/ /
  \__ \/ _ \/ ___/ ___/ __/ __/ /_/ / __ \/ / / / __ \/ __  / 
 ___/ /  __/ /__/ /  / /_/ /_/ __  / /_/ / /_/ / / / / /_/ /  
/____/\___/\___/_/   \__/\__/_/ /_/\____/\__,_/_/ /_/\__,_/   v%s
`
	fmt.Fprintf(os.Stderr, banner, cmd.Version)
}
