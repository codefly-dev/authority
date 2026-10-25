package workcontext_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"google.golang.org/grpc/metadata"
	"os"
	"strings"
	"testing"

	reader "github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

type fixture struct {
	Name, Token, Audience string
	Scopes                []*basev0.WorkScopeV1
	Probes                []struct {
		Kind, Action string
		ResourceID   string `json:"resource_id"`
		Allowed      bool
	}
}

func fixtures(t *testing.T) []fixture {
	t.Helper()
	data, err := os.ReadFile("../../testdata/claims.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []fixture
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func body(t *testing.T, name string) *basev0.WorkContextV1 {
	t.Helper()
	for _, f := range fixtures(t) {
		if f.Name == name {
			d, err := core.Decode(f.Token)
			if err != nil {
				t.Fatal(err)
			}
			return d.Context()
		}
	}
	t.Fatal("fixture missing")
	return nil
}

// Synthetic signatures test projection only; they are not authenticated tokens.
func tokenFor(t *testing.T, c *basev0.WorkContextV1) string {
	t.Helper()
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
}
func read(t *testing.T, c *basev0.WorkContextV1) *reader.Claims {
	t.Helper()
	out, err := readToken(tokenFor(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestCoreFixtures(t *testing.T) {
	for _, f := range fixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			c, err := readToken(f.Token)
			if err != nil {
				t.Fatal(err)
			}
			if c.Audience() != f.Audience {
				t.Fatal("audience differs")
			}
			scopes := c.Scopes()
			if len(scopes) != len(f.Scopes) {
				t.Fatal("effective scope count differs")
			}
			for n, scope := range scopes {
				if !proto.Equal(scope, f.Scopes[n]) {
					t.Fatalf("scope %d differs", n)
				}
			}
			for _, p := range f.Probes {
				if c.Allows(p.Kind, p.Action, p.ResourceID) != p.Allowed {
					t.Fatalf("probe %s %s %s", p.Kind, p.Action, p.ResourceID)
				}
			}
		})
	}
}
func TestSeparateGrantsAndWholeKind(t *testing.T) {
	c := body(t, "session")
	c.AuthorityScopes = []*basev0.WorkScopeV1{
		{ResourceKind: "record", Actions: []string{"read"}, ResourceIds: []string{"a"}},
		{ResourceKind: "record", Actions: []string{"invoke"}, ResourceIds: []string{"b"}},
	}
	claims := read(t, c)
	for _, q := range []struct {
		action, id string
		allowed    bool
	}{{"read", "a", true}, {"invoke", "b", true}, {"invoke", "a", false}, {"read", "b", false}, {"read", "", false}} {
		if claims.Allows("record", q.action, q.id) != q.allowed {
			t.Fatal(q)
		}
	}
	copied := claims.Scopes()
	copied[0].Actions = append(copied[0].Actions, "invoke")
	copied[0].ResourceIds = append(copied[0].ResourceIds, "b")
	if claims.Allows("record", "invoke", "a") {
		t.Fatal("mutable scope escaped")
	}
	c.AuthorityScopes = []*basev0.WorkScopeV1{{ResourceKind: "record", Actions: []string{"read", "admin", "*"}}}
	claims = read(t, c)
	if !claims.Allows("record", "read", "") || !claims.Allows("record", "read", "a") || claims.Allows("record", "invoke", "a") || claims.Allows("", "read", "") || claims.Allows("record", "", "") {
		t.Fatal("literal scope semantics changed")
	}
	var empty reader.Claims
	if empty.Allows("record", "read", "") {
		t.Fatal("zero claims grant authority")
	}
}
func TestEmptyFinalActorGrantsNothing(t *testing.T) {
	c := body(t, "delegated")
	c.ActorChain[len(c.ActorChain)-1].GrantedScopes = nil
	claims := read(t, c)
	if len(claims.Scopes()) != 0 || claims.Allows("record", "read", "record-conformance") {
		t.Fatal("earlier scopes leaked")
	}
}
func TestUnreadableContexts(t *testing.T) {
	valid := tokenFor(t, body(t, "session"))
	payload, _, _ := strings.Cut(valid, ".")
	for _, token := range []string{"", "abc", "a.b.c", ".", "é.x", strings.Repeat("a", 32*1024+1), valid + "=", payload + ".AA", payload + "." + strings.Repeat("A", 85) + "B"} {
		if _, err := readToken(token); !errors.Is(err, reader.ErrUnreadableContext) {
			t.Fatalf("envelope not refused: %v", err)
		}
	}
	for _, where := range []string{"root", "nested", "duplicate", "audience", "structural"} {
		t.Run(where, func(t *testing.T) {
			c := body(t, "session")
			switch where {
			case "root":
				c.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			case "nested":
				c.AuthorityScopes[0].ProtoReflect().SetUnknown([]byte{0x78, 0x01})
			case "audience":
				c.Audience = ""
			case "structural":
				c.Seal = nil
			}
			token := tokenFor(t, c)
			if where == "duplicate" {
				p, s, _ := strings.Cut(token, ".")
				b, _ := base64.RawURLEncoding.DecodeString(p)
				token = base64.RawURLEncoding.EncodeToString(append(b, b...)) + "." + s
			}
			if _, err := readToken(token); !errors.Is(err, reader.ErrUnreadableContext) {
				t.Fatalf("malformed claims not refused: %v", err)
			}
		})
	}
}

func stampedToken(token string) metadata.MD {
	sum := sha256.Sum256([]byte(token))
	return metadata.Pairs("x-codefly-work-context", token, "x-codefly-hop-proof", "test-proof", "x-codefly-hop-context", hex.EncodeToString(sum[:]))
}
func readToken(token string) (*reader.Claims, error) {
	return reader.ReadClaims(stampedToken(token), "test-proof")
}
func TestReadClaimsRequiresTheStamp(t *testing.T) {
	token := fixtures(t)[0].Token
	for _, change := range []func(metadata.MD){
		func(md metadata.MD) { md.Delete("x-codefly-hop-proof") },
		func(md metadata.MD) { md.Set("x-codefly-hop-proof", "forged") },
		func(md metadata.MD) { md.Delete("x-codefly-hop-context") },
		func(md metadata.MD) { md.Set("x-codefly-work-context", token+"forged") },
		func(md metadata.MD) { md.Append("x-codefly-work-context", token) },
	} {
		md := stampedToken(token)
		change(md)
		if _, err := reader.ReadClaims(md, "test-proof"); !errors.Is(err, reader.ErrUnreadableContext) {
			t.Fatalf("unbound claims accepted: %v", err)
		}
	}
	if _, err := reader.ReadClaims(stampedToken(token), ""); err == nil {
		t.Fatal("empty proof accepted")
	}
}
