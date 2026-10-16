// Command capture runs the validator the way the README shows it, writes its
// untrimmed output and a provenance record under docs/captures/, and rewrites
// the excerpt under the README's caption for that command.
//
//	cd tests/validate
//	go run -mod=vendor ./capture
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	command    = "go run -mod=vendor ."
	directory  = "tests/validate"
	outputPath = "docs/captures/validate.txt"
	recordPath = "docs/captures/validate.json"
	readmePath = "README.md"
	elision    = "..."
	fence      = "```"
)

// record is the provenance written beside the output. Excerpt holds the
// 1-based inclusive line ranges of the output that the README shows.
type record struct {
	Command     string   `json:"command"`
	Directory   string   `json:"directory"`
	Version     string   `json:"version"`
	Uncommitted []string `json:"uncommitted"`
	Fixture     string   `json:"fixture"`
	Date        string   `json:"date"`
	ExitCode    int      `json:"exitCode"`
	Output      string   `json:"output"`
	Excerpt     [][2]int `json:"excerpt"`
}

func main() {
	root := flag.String("root", "../..", "repository root")
	flag.Parse()
	if err := capture(*root); err != nil {
		fmt.Fprintln(os.Stderr, "capture:", err)
		os.Exit(1)
	}
}

func capture(root string) error {
	abs := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }

	version, err := git(root, "describe", "--tags", "--always")
	if err != nil {
		return err
	}
	status, err := git(root, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	uncommitted := []string{}
	for _, line := range strings.Split(status, "\n") {
		if len(line) < 4 {
			continue
		}
		path := line[3:]
		if path == outputPath || path == recordPath || path == readmePath {
			continue
		}
		uncommitted = append(uncommitted, path)
	}

	cmd := exec.Command("go", "run", "-mod=vendor", ".")
	cmd.Dir = abs(directory)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	date := time.Now().UTC().Format(time.RFC3339)
	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return fmt.Errorf("%s: %v", command, err)
		}
		exitCode = exit.ExitCode()
	}
	if exitCode != 0 {
		os.Stderr.Write(out.Bytes())
		return fmt.Errorf("%s exited %d; the README shows a passing run, so nothing was written", command, exitCode)
	}

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	ranges := excerptRanges(lines)
	block, trimmed := excerpt(lines, ranges)
	caption := "What `" + command + "` prints"
	if trimmed {
		caption += ", trimmed"
	}
	caption += " ([full output](" + outputPath + ")):"

	rec := record{
		Command:     command,
		Directory:   directory,
		Version:     version,
		Uncommitted: uncommitted,
		Fixture:     "signatures/, tests/fixtures/, schema/, retired-ids.yaml, crosswalks/ and vendor/ of this repository at the recorded version",
		Date:        date,
		ExitCode:    exitCode,
		Output:      outputPath,
		Excerpt:     ranges,
	}
	recJSON, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(abs(outputPath)), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(abs(outputPath), out.Bytes(), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(abs(recordPath), append(recJSON, '\n'), 0o644); err != nil {
		return err
	}
	if err := rewriteReadme(abs(readmePath), caption, block); err != nil {
		return err
	}
	fmt.Printf("wrote %s, %s and the excerpt in %s\n", outputPath, recordPath, readmePath)
	return nil
}

// git runs a git command at root and returns its output without the
// trailing newline.
func git(root string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

// excerptRanges picks the lines the README shows: the first and the last
// check, the first warning, and the summary with the blank line above it.
// Adjacent picks are merged into one range.
func excerptRanges(lines []string) [][2]int {
	picked := map[int]bool{}
	firstCheck, lastCheck, firstWarning := -1, -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "ok   check") || strings.HasPrefix(l, "FAIL check") {
			if firstCheck < 0 {
				firstCheck = i
			}
			lastCheck = i
		}
		if firstWarning < 0 && strings.HasPrefix(l, "WARNING ") {
			firstWarning = i
		}
	}
	for _, i := range []int{firstCheck, lastCheck, firstWarning} {
		if i >= 0 {
			picked[i] = true
		}
	}
	last := len(lines) - 1
	picked[last] = true
	if last > 0 && lines[last-1] == "" {
		picked[last-1] = true
	}

	var ranges [][2]int
	for i := range lines {
		if !picked[i] {
			continue
		}
		if n := len(ranges); n > 0 && ranges[n-1][1] == i {
			ranges[n-1][1] = i + 1
			continue
		}
		ranges = append(ranges, [2]int{i + 1, i + 1})
	}
	return ranges
}

// excerpt renders the ranges with an elision line in place of each gap and
// reports whether any line was elided.
func excerpt(lines []string, ranges [][2]int) ([]string, bool) {
	var block []string
	trimmed := false
	next := 1
	for _, r := range ranges {
		if r[0] > next {
			block = append(block, elision)
			trimmed = true
		}
		block = append(block, lines[r[0]-1:r[1]]...)
		next = r[1] + 1
	}
	if next <= len(lines) {
		block = append(block, elision)
		trimmed = true
	}
	return block, trimmed
}

// rewriteReadme replaces the caption line for the command and the fenced
// block after it. The caption must be followed by a blank line and a fence.
func rewriteReadme(path, caption string, block []string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	prefix := "What `" + command + "` prints"
	at := -1
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			at = i
			break
		}
	}
	if at < 0 {
		return fmt.Errorf("%s has no line starting %q", readmePath, prefix)
	}
	if at+2 >= len(lines) || lines[at+1] != "" || lines[at+2] != fence {
		return fmt.Errorf("%s: the caption on line %d must be followed by a blank line and a %s fence", readmePath, at+1, fence)
	}
	end := -1
	for i := at + 3; i < len(lines); i++ {
		if lines[i] == fence {
			end = i
			break
		}
	}
	if end < 0 {
		return fmt.Errorf("%s: the fence after the caption on line %d is not closed", readmePath, at+1)
	}

	var rewritten []string
	rewritten = append(rewritten, lines[:at]...)
	rewritten = append(rewritten, caption, "", fence)
	rewritten = append(rewritten, block...)
	rewritten = append(rewritten, lines[end:]...)
	return os.WriteFile(path, []byte(strings.Join(rewritten, "\n")), 0o644)
}
