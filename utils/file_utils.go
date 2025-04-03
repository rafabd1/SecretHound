package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// FindLineNumber locates the line number of a string in content
func FindLineNumber(content, value string) int {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, value) {
			return i + 1 // Line numbers start at 1
		}
	}
	return 0 // Not found
}

// IsBinaryContent checks if content appears to be binary data
func IsBinaryContent(content []byte) bool {
	// If the content contains a high percentage of null bytes or control characters, it's likely binary
	controlCount := 0
	nullCount := 0
	maxCheckLength := 1024 // Only check the first 1KB to save time
	
	if len(content) == 0 {
		return false
	}
	
	checkLength := min(len(content), maxCheckLength)
	
	for i := 0; i < checkLength; i++ {
		c := content[i]
		if c == 0 {
			nullCount++
		} else if c < 32 && c != '\n' && c != '\r' && c != '\t' {
			controlCount++
		}
	}
	
	// If more than 10% is control or null characters, likely binary
	return float64(controlCount+nullCount)/float64(checkLength) > 0.1
}

// max returns the larger of a and b
func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// Helper for min function (Go 1.21+ has this in the standard library)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IsBinaryFile checks if a file appears to be binary
func IsBinaryFile(path string) bool {
	// Skip files with binary extensions
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".exe", ".dll", 
	     ".so", ".dylib", ".bin", ".o", ".obj", ".a", ".lib", ".zip", 
		 ".tar", ".gz", ".7z", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
		 ".ppt", ".pptx", ".mp3", ".mp4", ".avi", ".mov", ".flv", ".ttf",
		 ".woff", ".woff2", ".eot", ".class", ".jar":
		return true
	}

	// Read a small portion of the file to check
	f, err := os.Open(path)
	if err != nil {
		return false // If we can't read it, assume it's not binary for now
	}
	defer f.Close()

	// Read first 512 bytes to check for binary content
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false // Error reading or empty file
	}

	return IsBinaryContent(buf[:n])
}

// GetFileExtension returns the file extension in lowercase
func GetFileExtension(path string) string {
	return strings.ToLower(filepath.Ext(path))
}

// IsTextFile checks if a file appears to be a text file by its extension
func IsTextFile(path string) bool {
	ext := GetFileExtension(path)
	
	// Common text file extensions
	textExtensions := map[string]bool{
		".txt": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
		".html": true, ".htm": true, ".css": true, ".json": true,
		".xml": true, ".yaml": true, ".yml": true, ".md": true,
		".csv": true, ".ini": true, ".conf": true, ".config": true,
		".go": true, ".py": true, ".java": true, ".c": true, ".cpp": true,
		".h": true, ".hpp": true, ".cs": true, ".php": true, ".rb": true,
		".pl": true, ".sql": true, ".sh": true, ".bat": true, ".ps1": true,
	}
	
	return textExtensions[ext] || ext == "" // Files without extension might be text
}
