package noproxygate

import (
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// packageInventory names directories explicitly: ./... silently drops _, . and
// testdata directories, even when production code imports them. Production
// build constraints are refused regardless of whether today's build selects
// them. Platform filenames are refused even on the selected platform, and a
// final coverage check rejects any source omitted by the loader.
func packageInventory(root, dir string, overlay map[string][]byte) ([]string, []Violation, error) {
	sources := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("cannot judge symlink %s: %w", path, err)
			}
			if target.IsDir() || strings.HasSuffix(path, ".go") {
				return fmt.Errorf("%s: production source symlinks are refused because they escape the module inventory", path)
			}
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			if path != dir {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
		} else if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			sources[path] = true
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	for path := range overlay {
		relative, err := filepath.Rel(dir, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			sources[path] = true
		}
	}
	dirs := map[string]bool{}
	var violations []Violation
	for path := range sources {
		source, ok := overlay[path]
		if !ok {
			source, err = os.ReadFile(path)
			if err != nil {
				return nil, nil, err
			}
		}
		files := token.NewFileSet()
		file, err := parser.ParseFile(files, path, source, parser.ParseComments)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot judge production source %s: %w", path, err)
		}
		relative, _ := filepath.Rel(root, path)
		refuse := func(line int, reason string) {
			violations = append(violations, Violation{filepath.ToSlash(relative), line, reason})
		}
		for _, group := range file.Comments {
			for _, comment := range group.List {
				if constraint.IsGoBuild(comment.Text) || constraint.IsPlusBuild(comment.Text) {
					refuse(files.Position(comment.Pos()).Line, "production build constraints are refused: every build must be judged, not only the current tag combination")
				}
			}
		}
		for _, spec := range file.Imports {
			name, _ := strconv.Unquote(spec.Path.Value)
			if name == "C" {
				refuse(files.Position(spec.Pos()).Line, `import "C" is refused: cgo rewrites the source before type checking`)
			}
		}
		// Let the go tool decide platform filename selection, then verify complete
		// source coverage after loading. Overlay-only files have no disk metadata.
		neutral := build.Default
		neutral.GOOS, neutral.GOARCH = "noproxygate", "noproxygate"
		universal, probeErr := neutral.MatchFile(filepath.Dir(path), filepath.Base(path))
		if probeErr == nil && !universal {
			refuse(1, "production build constraints or platform filenames are refused: every supported build must be judged")
		}
		active, err := build.Default.MatchFile(filepath.Dir(path), filepath.Base(path))
		if err != nil && !ok {
			return nil, nil, err
		}
		if active || ok {
			dirs[filepath.Dir(path)] = true
		}
	}
	patterns := make([]string, 0, len(dirs))
	for directory := range dirs {
		relative, _ := filepath.Rel(dir, directory)
		patterns = append(patterns, "./"+filepath.ToSlash(relative))
	}
	sort.Strings(patterns)
	return patterns, violations, nil
}
