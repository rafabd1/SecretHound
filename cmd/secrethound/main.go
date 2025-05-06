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

	// printBanner() // REMOVED - Header is now printed conditionally in runScan
	
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
