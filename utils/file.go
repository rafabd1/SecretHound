package utils

import (
	"os"
)


// IsReadableFile checks if a file exists and is readable
func IsReadableFile(filePath string) bool {
	// Try to open the file
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

// GetFileInfo gets detailed information about a file
func GetFileInfo(filePath string) (os.FileInfo, error) {
	return os.Stat(filePath)
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(filePath string) (int64, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// IsDirectory checks if a path is a directory
func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
