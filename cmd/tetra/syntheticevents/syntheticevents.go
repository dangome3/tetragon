// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syntheticevents

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var (
	sourceFile string
	outputFile string
)

func generateCmd() *cobra.Command {
	ret := &cobra.Command{
		Use:   "generate",
		Short: "Generate a synthetic events file from Tetragon's export log",
		Long: `Read the events file and create a new log file in the current 
directory with the same information.

Examples:
  # Generate synthetic events using the configured export file
  tetra synthetic-events generate

  # Generate synthetic events from a specific file
  tetra synthetic-events generate --source /var/log/tetragon/tetragon.log

  # Generate synthetic events with custom output filename
  tetra synthetic-events generate --output my-events.log`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no export file specified, try to get it from init info
			if sourceFile == "" {
				sourceFile = "/var/log/tetragon/tetragon.log"
			}

			// Check if the export file exists
			if _, err := os.Stat(sourceFile); os.IsNotExist(err) {
				return fmt.Errorf("export file does not exist: %s", sourceFile)
			}

			// Generate output filename if not specified
			if outputFile == "" {
				timestamp := time.Now().Format("20060102-150405")
				outputFile = fmt.Sprintf("synthetic-events-%s.log", timestamp)
			}

			// Parses the export file to the output file
			if err := parseEventsFile(sourceFile, outputFile); err != nil {
				return fmt.Errorf("failed to generate synthetic events file: %w", err)
			}

			cmd.Printf("Successfully generated synthetic events file: %s\n", outputFile)
			cmd.Printf("Source: %s\n", sourceFile)

			return nil
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&sourceFile, "source", "s", "", "Path to the Tetragon export file (defaults to configured export filename)")
	flags.StringVarP(&outputFile, "output", "o", "", "Output filename (defaults to synthetic-events-<timestamp>.log)")

	return ret
}

func parseEventsFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Get absolute path for output
	dstPath, err := filepath.Abs(dst)
	if err != nil {
		dstPath = dst
	}

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
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
			return fmt.Errorf("failed to transform event at line %d: %w", lineNum, err)
		}

		if _, err := writer.Write(transformed); err != nil {
			return fmt.Errorf("failed to write event at line %d: %w", lineNum, err)
		}
		if _, err := writer.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write newline at line %d: %w", lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading source file: %w", err)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush output: %w", err)
	}

	return nil
}

// transformEvent wraps the original event with ktime, type, and event fields
func transformEvent(line []byte) ([]byte, error) {
	// Parse the original event
	var original map[string]json.RawMessage
	if err := json.Unmarshal(line, &original); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Detect the event type (first key that looks like an event type)
	eventType := detectEventType(original)
	if eventType == "" {
		return nil, fmt.Errorf("could not detect event type")
	}

	// Extract the time field for ktime
	var ktime string
	if timeRaw, ok := original["time"]; ok {
		json.Unmarshal(timeRaw, &ktime)
	}

	// Build the wrapped event
	wrapped := map[string]interface{}{
		"ktime": ktime,
		"type":  eventType,
		"event": original,
	}

	return json.Marshal(wrapped)
}

// detectEventType finds the event type from the JSON keys
func detectEventType(event map[string]json.RawMessage) string {
	// Known event type keys in Tetragon
	eventTypes := []string{
		"process_exec",
		"process_exit",
		"process_kprobe",
		"process_tracepoint",
		"process_uprobe",
		"process_loader",
		"process_lsm",
		"test",
		"rate_limit_info",
	}

	for _, et := range eventTypes {
		if _, ok := event[et]; ok {
			return et
		}
	}

	return ""
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "synthetic-events",
		Short: "Manage synthetic events",
		Long:  "Commands for generating and managing synthetic Tetragon events.",
	}

	cmd.AddCommand(
		generateCmd(),
	)

	return cmd
}
