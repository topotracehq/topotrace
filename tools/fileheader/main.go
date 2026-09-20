/*******************************************************************************
 * @file         main.go
 * @brief        Command fileheader stamps every source file in the repository with the TopoTrace LLC file header (see headerFor for the exact text per language) -- idempotent, so it can be re-run after adding files: a file that already carries the header is left alone.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command fileheader stamps every source file in the repository with the
// TopoTrace LLC file header (see headerFor for the exact
// text per language) -- idempotent, so it can be re-run after adding
// files: a file that already carries the header is left alone.
//
//	go run ./tools/fileheader          # stamp everything under the repo root
//	go run ./tools/fileheader -check   # exit 1 if any file is missing it (for CI)
//
// The @brief line is filled from the file's own leading comment (its
// package or module doc), the @date from the file's first git commit,
// so the header records something true about each file rather than a
// placeholder. Go files that start with a //go:build constraint keep it
// first, as the toolchain requires.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	company = "TopoTrace LLC"
	project = "Muster"
	author  = "Michael McGinnis"
	version = "1.0.0"
	marker  = "Copyright (c) 2026 " + company
)

var skipDirs = map[string]bool{".git": true, "vendor": true, "node_modules": true, "build": true, ".gradle": true, ".idea": true}

type style struct {
	open, line, close string
}

var styles = map[string]style{
	".go":    {"/*******************************************************************************", " * ", " ******************************************************************************/"},
	".js":    {"/*******************************************************************************", " * ", " ******************************************************************************/"},
	".css":   {"/*******************************************************************************", " * ", " ******************************************************************************/"},
	".kt":    {"/*******************************************************************************", " * ", " ******************************************************************************/"},
	".swift": {"/*******************************************************************************", " * ", " ******************************************************************************/"},
	".html":  {"<!--", "  ", "-->"},
	".sh":    {"#" + strings.Repeat("#", 79), "# ", "#" + strings.Repeat("#", 79)},
	".ps1":   {"#" + strings.Repeat("#", 79), "# ", "#" + strings.Repeat("#", 79)},
	".sql":   {"--" + strings.Repeat("-", 78), "-- ", "--" + strings.Repeat("-", 78)},
	".yaml":  {"#" + strings.Repeat("#", 79), "# ", "#" + strings.Repeat("#", 79)},
	".yml":   {"#" + strings.Repeat("#", 79), "# ", "#" + strings.Repeat("#", 79)},
}

func main() {
	check := flag.Bool("check", false, "report files missing the header and exit 1 instead of stamping them")
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	missing := 0
	err := filepath.WalkDir(*root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != *root {
				return filepath.SkipDir
			}
			return nil
		}
		st, ok := styles[filepath.Ext(path)]
		if !ok {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(src, []byte(marker)) {
			return nil
		}
		missing++
		if *check {
			fmt.Println("missing header:", path)
			return nil
		}
		out := stamp(path, src, st)
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return err
		}
		fmt.Println("stamped", path)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *check && missing > 0 {
		os.Exit(1)
	}
}

// stamp returns src with the header prepended, preserving a shebang,
// a //go:build constraint block, or an HTML doctype as the true first
// line(s) where the language requires it.
func stamp(path string, src []byte, st style) []byte {
	header := headerFor(path, src, st)
	text := string(src)
	var prefix string
	switch {
	case strings.HasPrefix(text, "#!"):
		i := strings.Index(text, "\n")
		prefix, text = text[:i+1], text[i+1:]
	case strings.HasPrefix(text, "//go:build"):
		i := strings.Index(text, "\n\n")
		if i < 0 {
			i = strings.Index(text, "\n")
		}
		prefix, text = text[:i+1]+"\n", strings.TrimLeft(text[i+1:], "\n")
	case strings.HasPrefix(strings.ToLower(text), "<!doctype"):
		i := strings.Index(text, "\n")
		prefix, text = text[:i+1], text[i+1:]
	}
	return []byte(prefix + header + "\n" + text)
}

func headerFor(path string, src []byte, st style) string {
	brief := firstComment(src, filepath.Ext(path))
	if brief == "" {
		if strings.HasSuffix(path, "_test.go") {
			brief = "Tests for the " + project + " " + filepath.Base(filepath.Dir(path)) + " package."
		} else {
			brief = "Part of the " + project + " " + filepath.Base(filepath.Dir(path)) + " module."
		}
	}
	date := firstCommitDate(path)
	lines := []string{
		"@file         " + filepath.Base(path),
		"@brief        " + brief,
		"@project      " + project,
		"",
		"@author       " + author,
		"@date         " + date,
		"@version      " + version,
		"",
		marker + ". All rights reserved.",
		"Licensed under the MIT License -- see the LICENSE file at the repository root.",
	}
	var b strings.Builder
	b.WriteString(st.open + "\n")
	for _, l := range lines {
		b.WriteString(strings.TrimRight(st.line+l, " ") + "\n")
	}
	b.WriteString(st.close + "\n")
	return b.String()
}

// firstComment pulls the first sentence of the file's leading comment
// block (package doc for Go, a top-of-file comment elsewhere), which is
// the most honest one-line description the file already has.
func firstComment(src []byte, ext string) string {
	sc := bufio.NewScanner(bytes.NewReader(src))
	var words []string
	started := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" && !started {
			continue
		}
		if strings.HasPrefix(line, "#!") || strings.HasPrefix(line, "//go:build") || strings.HasPrefix(line, "<!doctype") || strings.HasPrefix(line, "<!DOCTYPE") {
			continue
		}
		var body string
		switch {
		case strings.HasPrefix(line, "//"):
			body = strings.TrimSpace(strings.TrimPrefix(line, "//"))
		case strings.HasPrefix(line, "#") && (ext == ".sh" || ext == ".ps1" || ext == ".yaml" || ext == ".yml"):
			body = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		case strings.HasPrefix(line, "--") && ext == ".sql":
			body = strings.TrimSpace(strings.TrimPrefix(line, "--"))
		case strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "<!--"):
			body = strings.TrimSpace(strings.TrimLeft(line, "/*<!- "))
		default:
			if started {
				break
			}
			return ""
		}
		if body == "" && started {
			break
		}
		if body == "" {
			continue
		}
		started = true
		words = append(words, body)
		joined := strings.Join(words, " ")
		if i := strings.Index(joined, ". "); i > 0 {
			return strings.ReplaceAll(joined[:i+1], "  ", " ")
		}
		if strings.HasSuffix(joined, ".") {
			return joined
		}
		if len(joined) > 240 {
			return joined[:237] + "..."
		}
	}
	joined := strings.Join(words, " ")
	if len(joined) > 240 {
		return joined[:237] + "..."
	}
	return joined
}

func firstCommitDate(path string) string {
	out, err := exec.Command("git", "log", "--diff-filter=A", "--follow", "--format=%as", "--", path).Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
			return last
		}
	}
	return time.Now().UTC().Format("2006-01-02")
}
