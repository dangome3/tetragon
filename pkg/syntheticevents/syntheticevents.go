// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syntheticevents

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
)

var (
	log = logger.GetLogger()
)

func ParseEventsFile(src string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		log.Error("Synthetic Events: failed to open source file")
		return err
	}
	defer srcFile.Close()

	// Derive destination path: src=/path/to/file.log -> dst=/path/to/file-synthetic-events.log
	ext := filepath.Ext(src)
	dstFile, err := os.Create(strings.TrimSuffix(src, ext) + "-synthetic-events" + ext)
	if err != nil {
		log.Error("Synthetic Events: failed to create destination file")
		return err
	}
	defer dstFile.Close()

	scanner := bufio.NewScanner(srcFile)
	writer := bufio.NewWriter(dstFile)

	// Increase scanner buffer for potentially large JSON lines
	const maxScannerSize = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxScannerSize)
	scanner.Buffer(buf, maxScannerSize)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		transformed, err := transformEvent(line)
		if err != nil {
			log.Error("Synthetic Events: failed to transform event", "line", lineNum)
			return err
		}

		writer.Write(transformed)
		writer.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		log.Error("Synthetic Events: error reading source file")
		return err
	}

	if err := writer.Flush(); err != nil {
		log.Error("Synthetic Events: failed to flush output")
		return err
	}

	log.Info("Synthetic events file created successfully.")
	return nil
}

func transformEvent(line []byte) ([]byte, error) {
	var original map[string]json.RawMessage
	if err := json.Unmarshal(line, &original); err != nil {
		return nil, err
	}

	eventType := detectEventType(original)
	if eventType == "" {
		return nil, errors.New("could not detect event type")
	}

	var ktime string
	if timeRaw, ok := original["time"]; ok {
		json.Unmarshal(timeRaw, &ktime)
	}

	wrapped := map[string]interface{}{
		"ktime": ktime,
		"type":  eventType,
		"event": original,
	}

	return json.Marshal(wrapped)
}

func detectEventType(event map[string]json.RawMessage) string {
	eventTypes := []string{
		"process_exec",
		"process_exit",
		"process_kprobe",
		"process_tracepoint",
		"process_uprobe",
		"process_loader",
		"process_lsm",
		"rate_limit_info",
	}

	for _, et := range eventTypes {
		if _, ok := event[et]; ok {
			return et
		}
	}

	return ""
}
