package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// IsBinaryFile checks if a file is likely a binary file
func IsBinaryFile(filePath string) bool {
	// Check extension first
	ext := strings.ToLower(filepath.Ext(filePath))
	if isBinaryExtension(ext) {
		return true
	}
	
	// Check file size (quick check to avoid reading very large files)
	fileInfo, err := os.Stat(filePath)
	if err == nil && fileInfo.Size() > 10*1024*1024 { // 10MB
		return true // Consider very large files as binary
	}
	
	// Read a sample to check content
	file, err := os.Open(filePath)
	if err != nil {
		// If we can't open the file, we'll assume it's not binary
		return false
	}
	defer file.Close()
	
	// Read the first 512 bytes
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	
	// Check if the content appears to be binary
	return IsBinaryContent(buf[:n])
}

// IsBinaryContent checks if byte content appears to be binary
func IsBinaryContent(content []byte) bool {
	// Simple heuristic: count control characters and null bytes
	controlCount := 0
	nullCount := 0
	
	// Only check the first 512 bytes max
	checkLength := len(content)
	if checkLength > 512 {
		checkLength = 512
	}
	
	for i := 0; i < checkLength; i++ {
		if content[i] == 0 {
			nullCount++
		} else if content[i] < 32 && content[i] != 9 && content[i] != 10 && content[i] != 13 {
			// Not counting tab, LF, or CR
			controlCount++
		}
	}
	
	// If more than 10% of the first bytes are control/null chars, likely binary
	threshold := checkLength / 10
	return nullCount > threshold || controlCount > threshold
}

// isBinaryExtension checks if a file extension typically indicates a binary file
func isBinaryExtension(ext string) bool {
	binaryExtensions := map[string]bool{
		".exe":  true,
		".dll":  true,
		".so":   true,
		".dylib": true,
		".bin":  true,
		".obj":  true,
		".o":    true,
		".a":    true,
		".lib":  true,
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".bmp":  true,
		".ico":  true,
		".webp": true,
		".mp3":  true,
		".mp4":  true,
		".mov":  true,
		".avi":  true,
		".wmv":  true,
		".zip":  true,
		".tar":  true,
		".gz":   true,
		".7z":   true,
		".rar":  true,
		".jar":  true,
		".war":  true,
		".ear":  true,
		".pdf":  true,
		".doc":  true,
		".docx": true,
		".xls":  true,
		".xlsx": true,
		".ppt":  true,
		".pptx": true,
	}
	
	return binaryExtensions[ext]
}

// IsTextFile checks if a file is likely a text file
func IsTextFile(filePath string) bool {
	return !IsBinaryFile(filePath)
}

// Adjust to ensure text files with unusual names are processed
func isTextFileExtension(ext string) bool {
    textExtensions := map[string]bool{
        ".js":     true,
        ".jsx":    true,
        ".ts":     true,
        ".tsx":    true,
        ".html":   true,
        ".htm":    true,
        ".css":    true,
        ".scss":   true,
        ".less":   true,
        ".json":   true,
        ".xml":    true,
        ".yaml":   true,
        ".yml":    true,
        ".md":     true,
        ".txt":    true,
        ".csv":    true,
        ".tsv":    true,
        ".log":    true,
        ".config": true,
        ".conf":   true,
        ".ini":    true,
        ".properties": true,
        ".gradle": true,
        ".sh":     true,
        ".bat":    true,
        ".cmd":    true,
        ".ps1":    true,
        ".py":     true,
        ".java":   true,
        ".c":      true,
        ".cpp":    true,
        ".h":      true,
        ".hpp":    true,
        ".go":     true,
        ".rb":     true,
        ".php":    true,
        ".pl":     true,
        ".sql":    true,
    }
    
    return textExtensions[ext]
}

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

// GetFileExtension returns the extension of a file
func GetFileExtension(filePath string) string {
	return strings.ToLower(filepath.Ext(filePath))
}

// IsDirectory checks if a path is a directory
func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
