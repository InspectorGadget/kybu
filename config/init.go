package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func ToggleCSM(enable bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".aws", "config")

	// Open file for Reading and Writing
	file, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var output []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 1. Identification: Detect Profile Headers
		isProfileHeader := strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && (trimmed == "[default]" || strings.HasPrefix(trimmed, "[profile "))
		if strings.HasPrefix(trimmed, "csm_enabled") {
			continue
		}

		// 2. Keep the original line (headers, regions, output format, etc.)
		output = append(output, line)

		// 3. Injection Logic
		if enable && isProfileHeader {
			output = append(output, "csm_enabled = true")
		}
	}

	// 4. Write changes back to disk
	file.Truncate(0)
	file.Seek(0, 0)
	writer := bufio.NewWriter(file)
	for _, line := range output {
		writer.WriteString(line + "\n")
	}

	return writer.Flush()
}
