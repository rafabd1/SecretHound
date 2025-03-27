#!/bin/bash

# Build script for SecretHound

VERSION=$(grep -oP 'Version = "\K[^"]+' cmd/version.go)
echo "Building SecretHound v$VERSION..."

# Create build directory
mkdir -p bin

# Build for current platform
echo "Building for current platform..."
go build -o bin/secrethound ./cmd/secrethound

# Cross-compile for other platforms (optional)
if [ "$1" == "release" ]; then
    echo "Building release binaries..."
    
    # Linux (64-bit)
    GOOS=linux GOARCH=amd64 go build -o bin/secrethound-linux-amd64 ./cmd/secrethound
    
    # Windows (64-bit)
    GOOS=windows GOARCH=amd64 go build -o bin/secrethound-windows-amd64.exe ./cmd/secrethound
    
    # macOS (64-bit)
    GOOS=darwin GOARCH=amd64 go build -o bin/secrethound-darwin-amd64 ./cmd/secrethound
    
    echo "Release binaries built in bin/ directory"
else
    echo "Built binary in bin/secrethound"
    echo "Run 'build.sh release' to build for all platforms."
fi
