package packagegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every module of the repository is deliverable as the package it declares.
func TestModules(t *testing.T) {
	modules, err := filepath.Glob(filepath.Join("..", "..", "modules", "*", "module.codefly.yaml"))
	if err != nil || len(modules) == 0 {
		t.Fatalf("no module found under modules/: %v", err)
	}
	for _, module := range modules {
		dir := filepath.Dir(module)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			if err := Check(dir); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The gate refuses what stopped a run: a module-identity module with no
// package manifest, and a contract its service's sources have moved past.
func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(t *testing.T, dir string)
		want   string
	}{
		"no package manifest": {
			mutate: func(t *testing.T, dir string) { remove(t, filepath.Join(dir, "module.package.codefly.yaml")) },
			want:   "declare module-identity",
		},
		"a proto moved": {
			mutate: func(t *testing.T, dir string) {
				appendTo(t, filepath.Join(dir, "services", "hop", "proto", "api.proto"), "\n// moved\n")
			},
			want: "contract hop/grpc is stale",
		},
		"a proto added": {
			mutate: func(t *testing.T, dir string) {
				appendTo(t, filepath.Join(dir, "services", "local", "proto", "host", "added.proto"), "syntax = \"proto3\";\n")
			},
			want: "added.proto is missing",
		},
		"an OpenAPI document moved": {
			mutate: func(t *testing.T, dir string) {
				appendTo(t, filepath.Join(dir, "services", "local", "openapi", "api.swagger.json"), " ")
			},
			want: "contract local/rest is stale",
		},
		"a contract file edited": {
			mutate: func(t *testing.T, dir string) {
				appendTo(t, filepath.Join(dir, "contracts", "api", "hop", "grpc", "contract.binpb"), "x")
			},
			want: "does not match catalog digest",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "modules", "authority"))); err != nil {
				t.Fatal(err)
			}
			c.mutate(t, dir)
			err := Check(dir)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Check() = %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func remove(t *testing.T, file string) {
	t.Helper()
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
}

func appendTo(t *testing.T, file, text string) {
	t.Helper()
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}
