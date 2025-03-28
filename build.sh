#!/bin/bash

# Build script for SecretHound
VERSION="0.1.1"
BUILD_DATE=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Display build info
echo "Building SecretHound $VERSION"
echo "Build Date: $BUILD_DATE"
echo "Git Commit: $GIT_COMMIT"

# Build for current platform
echo "Building for $(go env GOOS)/$(go env GOARCH)..."
go build -ldflags "-X github.com/rafabd1/SecretHound/cmd.Version=$VERSION -X 'github.com/rafabd1/SecretHound/cmd.BuildDate=$BUILD_DATE' -X github.com/rafabd1/SecretHound/cmd.GitCommit=$GIT_COMMIT" -o secrethound ./cmd/secrethound/

echo "Build complete: $(pwd)/secrethound"

# Build for all major platforms
if [ "$1" == "release" ]; then
    echo "Building release binaries for all platforms..."
    
    # Create output directory
    mkdir -p release
    
    # Build for Windows
    GOOS=windows GOARCH=amd64 go build -ldflags "-X github.com/rafabd1/SecretHound/cmd.Version=$VERSION -X 'github.com/rafabd1/SecretHound/cmd.BuildDate=$BUILD_DATE' -X github.com/rafabd1/SecretHound/cmd.GitCommit=$GIT_COMMIT" -o release/secrethound-$VERSION-windows-amd64.exe ./cmd/secrethound/
    
    # Build for Linux
    GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/rafabd1/SecretHound/cmd.Version=$VERSION -X 'github.com/rafabd1/SecretHound/cmd.BuildDate=$BUILD_DATE' -X github.com/rafabd1/SecretHound/cmd.GitCommit=$GIT_COMMIT" -o release/secrethound-$VERSION-linux-amd64 ./cmd/secrethound/
    
    # Build for macOS
    GOOS=darwin GOARCH=amd64 go build -ldflags "-X github.com/rafabd1/SecretHound/cmd.Version=$VERSION -X 'github.com/rafabd1/SecretHound/cmd.BuildDate=$BUILD_DATE' -X github.com/rafabd1/SecretHound/cmd.GitCommit=$GIT_COMMIT" -o release/secrethound-$VERSION-darwin-amd64 ./cmd/secrethound/
    
    echo "Release builds complete in $(pwd)/release/"
fi
