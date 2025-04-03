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

func resetGlobalState() {
    runtime.GC()
}

func main() {
    resetGlobalState()

	runtime.GOMAXPROCS(runtime.NumCPU())

	printBanner()
	
	setupSignalHandling()

	cmd.Execute()
}

func setupSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		fmt.Fprintln(os.Stderr, "\nReceived interrupt signal. Shutting down...")
		fmt.Fprintln(os.Stderr, "Please wait for active tasks to complete...")
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

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
