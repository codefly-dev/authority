package packagegate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
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
		"the hop's Version unmarked": {
			mutate: func(t *testing.T, dir string) {
				contract := filepath.Join(dir, "contracts", "api", "hop", "grpc", "contract.binpb")
				data, err := os.ReadFile(contract)
				if err != nil {
					t.Fatal(err)
				}
				var set descriptorpb.FileDescriptorSet
				if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).Unmarshal(data, &set); err != nil {
					t.Fatal(err)
				}
				for _, file := range set.GetFile() {
					for _, service := range file.GetService() {
						for _, method := range service.GetMethod() {
							if method.GetOptions() != nil {
								proto.ClearExtension(method.GetOptions(), hopv1.E_Policy)
							}
						}
					}
				}
				unmarked, err := proto.MarshalOptions{Deterministic: true}.Marshal(&set)
				if err != nil {
					t.Fatal(err)
				}
				redigest(t, dir, contract, unmarked)
			},
			want: "hop: /api.HopService/Version",
		},
		"a route no proto method binds, unmarked": {
			mutate: func(t *testing.T, dir string) {
				contract := filepath.Join(dir, "contracts", "api", "hop", "http", "openapi.json")
				data, err := os.ReadFile(contract)
				if err != nil {
					t.Fatal(err)
				}
				extra := strings.Replace(string(data), `"paths": {`, `"paths": {"/extra": {"get": {"operationId": "extra"}},`, 1)
				if extra == string(data) {
					t.Fatal("the hop's OpenAPI contract has no paths object")
				}
				redigest(t, dir, contract, []byte(extra))
				if err := os.WriteFile(filepath.Join(dir, "services", "hop", "openapi", "api.swagger.json"), []byte(extra), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "hop: GET /extra",
		},
		"a host-interface service that runs as the module": {
			mutate: func(t *testing.T, dir string) {
				appendTo(t, filepath.Join(dir, "services", "local", "service.codefly.yaml"), "module-identity: true\n")
			},
			want: "local: /host.authority.v1.AuthorityService/Issue",
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

// redigest writes a contract file and moves its digest in the package manifest
// and the catalog, as `codefly generate contracts` would.
func redigest(t *testing.T, dir, contract string, data []byte) {
	t.Helper()
	before, err := os.ReadFile(contract)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contract, data, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := func(b []byte) string { sum := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(sum[:]) }
	for _, file := range []string{filepath.Join(dir, "module.package.codefly.yaml"), filepath.Join(dir, "contracts", "api", "catalog.codefly.json")} {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		moved := strings.ReplaceAll(string(content), digest(before), digest(data))
		if moved == string(content) {
			t.Fatalf("%s names no digest of %s", file, contract)
		}
		if err := os.WriteFile(file, []byte(moved), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
