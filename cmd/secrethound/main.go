package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/rafabd1/SecretHound/cmd"
)

func main() {
	// Set GOMAXPROCS to use all available cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Print banner
	printBanner()
	
	// Setup signal handling for graceful exit
	setupSignalHandling()

	// Execute the root command
	cmd.Execute()
}

// setupSignalHandling configures graceful shutdown on Ctrl+C
func setupSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		fmt.Fprintln(os.Stderr, "\nReceived interrupt signal. Shutting down...")
		fmt.Fprintln(os.Stderr, "Please wait for active tasks to complete...")
		// Give a short delay for any cleanup that might be happening
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

// printBanner prints the application banner
func printBanner() {
	banner := `
   _____                   __  __  __                      __
  / ___/___  _____________/ /_/ / / /___  __  ______  ____/ /
  \__ \/ _ \/ ___/ ___/ __/ __/ /_/ / __ \/ / / / __ \/ __  / 
 ___/ /  __/ /__/ /  / /_/ /_/ __  / /_/ / /_/ / / / / /_/ /  
/____/\___/\___/_/   \__/\__/_/ /_/\____/\__,_/_/ /_/\__,_/   v%s

Secrets Finder | Created by github.com/rafabd1

`
	fmt.Fprintf(os.Stderr, banner, cmd.Version)
}
