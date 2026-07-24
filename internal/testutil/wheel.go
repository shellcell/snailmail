package testutil

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Wheel returns a deterministic, pure-Python wheel suitable for client tests.
func Wheel(name, version, requiresPython string) ([]byte, string, error) {
	return WheelWithDependencies(name, version, requiresPython, nil)
}

func WheelWithDependencies(name, version, requiresPython string, requirements []string) ([]byte, string, error) {
	distribution := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(name))
	module := distribution
	distInfo := distribution + "-" + version + ".dist-info"
	metadata := "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n"
	if requiresPython != "" {
		metadata += "Requires-Python: " + requiresPython + "\n"
	}
	for _, requirement := range requirements {
		metadata += "Requires-Dist: " + requirement + "\n"
	}
	metadata += "\n"
	files := []struct {
		name    string
		content string
	}{
		{name: module + "/__init__.py", content: "__version__ = " + fmt.Sprintf("%q", version) + "\n"},
		{name: distInfo + "/METADATA", content: metadata},
		{name: distInfo + "/WHEEL", content: "Wheel-Version: 1.0\nGenerator: snailmail-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"},
	}
	var record strings.Builder
	for _, file := range files {
		record.WriteString(file.name + ",,\n")
	}
	record.WriteString(distInfo + "/RECORD,,\n")
	files = append(files, struct {
		name    string
		content string
	}{name: distInfo + "/RECORD", content: record.String()})

	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, file := range files {
		header := &zip.FileHeader{Name: file.name, Method: zip.Store}
		header.SetModTime(time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC))
		header.SetMode(0o644)
		entry, err := archive.CreateHeader(header)
		if err != nil {
			return nil, "", err
		}
		if _, err := entry.Write([]byte(file.content)); err != nil {
			return nil, "", err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, "", err
	}
	filename := distribution + "-" + version + "-py3-none-any.whl"
	return buffer.Bytes(), filename, nil
}

func WriteWheel(directory, name, version, requiresPython string) (string, error) {
	return WriteWheelWithDependencies(directory, name, version, requiresPython, nil)
}

func WriteWheelWithDependencies(directory, name, version, requiresPython string, requirements []string) (string, error) {
	content, filename, err := WheelWithDependencies(name, version, requiresPython, requirements)
	if err != nil {
		return "", err
	}
	name = filepath.Join(directory, filename)
	if err := os.WriteFile(name, content, 0o644); err != nil {
		return "", err
	}
	return name, nil
}
