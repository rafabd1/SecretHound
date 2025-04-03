#!/bin/bash

# Build script for SecretHound
VERSION="0.2.0"

# Display build info
echo "Building SecretHound $VERSION"
echo "Platform: $(go env GOOS)/$(go env GOARCH)"

# Build for current platform
echo "Building for $(go env GOOS)/$(go env GOARCH)..."
go build -ldflags "-X github.com/rafabd1/SecretHound/cmd.Version=$VERSION" -o secrethound ./cmd/secrethound/

echo "Build complete: $(pwd)/secrethound"

# Build for all major platforms
if [ "$1" == "release" ]; then
    echo "Building release binaries for all platforms..."
    
    # Create output directory
    mkdir -p release
    
    # Build for Windows
    GOOS=windows GOARCH=amd64 go build -ldflags "-X github.com/rafabd1/SecretHound/cmd.Version=$VERSION" -o release/secrethound-$VERSION-windows-amd64.exe ./cmd/secrethound/
    
    # Build for Linux
    GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/rafabd1/SecretHound/cmd.Version=$VERSION" -o release/secrethound-$VERSION-linux-amd64 ./cmd/secrethound/
    
    # Build for macOS
    GOOS=darwin GOARCH=amd64 go build -ldflags "-X github.com/rafabd1/SecretHound/cmd.Version=$VERSION" -o release/secrethound-$VERSION-darwin-amd64 ./cmd/secrethound/
    
    echo "Release builds complete in $(pwd)/release/"
fi
