package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func FileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func DirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

func CreateDirIfNotExists(path string) error {
	if !DirExists(path) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

func GenerateTempFileName(prefix, suffix string) string {
	timestamp := Now().UnixNano()
	random := RandomString(8)
	return fmt.Sprintf("%s_%d_%s%s", prefix, timestamp, random, suffix)
}

func FindLineNumber(content, value string) int {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, value) {
			return i + 1
		}
	}
	return 0
}

func IsBinaryContent(content []byte) bool {
	controlCount := 0
	nullCount := 0
	maxCheckLength := 1024
	
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
	
	return float64(controlCount+nullCount)/float64(checkLength) > 0.1
}

func IsBinaryFile(path string) bool {
	// Common binary file extensions
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".exe", ".dll", 
		 ".so", ".dylib", ".bin", ".o", ".obj", ".a", ".lib", ".zip", 
		 ".tar", ".gz", ".7z", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
		 ".ppt", ".pptx", ".mp3", ".mp4", ".avi", ".mov", ".flv", ".ttf",
		 ".woff", ".woff2", ".eot", ".class", ".jar":
		return true
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	return IsBinaryContent(buf[:n])
}

func GetFileExtension(path string) string {
	return strings.ToLower(filepath.Ext(path))
}

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
	
	return textExtensions[ext] || ext == ""
}

func ReadLinesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()
	
	var lines []string
	scanner := bufio.NewScanner(file)
	
	const maxCapacity = 512 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	
	return lines, nil
}
