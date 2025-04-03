package utils

import (
	"os"
)

func IsReadableFile(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

func GetFileInfo(filePath string) (os.FileInfo, error) {
	return os.Stat(filePath)
}

func GetFileSize(filePath string) (int64, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
