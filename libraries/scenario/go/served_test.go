package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

// module writes a module directory that publishes one descriptor set
// declaring the services of package notes.v1 named, each with one method
// Get, and, when routed is not nil, a contract catalog whose one endpoint
// routes the services routed names.
func module(t *testing.T, declared []string, routed []string) string {
	t.Helper()
	dir := t.TempDir()
	file := &descriptorpb.FileDescriptorProto{Name: proto.String("notes.proto"), Package: proto.String("notes.v1"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Empty")}}}
	for _, service := range declared {
		file.Service = append(file.Service, &descriptorpb.ServiceDescriptorProto{Name: proto.String(service), Method: []*descriptorpb.MethodDescriptorProto{
			{Name: proto.String("Get"), InputType: proto.String(".notes.v1.Empty"), OutputType: proto.String(".notes.v1.Empty")}}})
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	if err != nil {
		t.Fatal(err)
	}
	at := filepath.Join(dir, "contracts", "api", "notes", "connect")
	if err := os.MkdirAll(at, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(at, "contract.binpb"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if routed == nil {
		return dir
	}
	sum := sha256.Sum256(raw)
	services := ""
	for i, service := range routed {
		if i > 0 {
			services += ","
		}
		services += fmt.Sprintf(`{"name":%q,"fullName":"notes.v1.%s","procedures":["/notes.v1.%s/Get"]}`, service, service, service)
	}
	catalog := fmt.Sprintf(`{"schema":"codefly/module-api-contracts/v1","package":"acme/notes","version":"0.1.0","endpoints":[
{"service":"notes","endpoint":"connect","api":"connect","kind":"protobuf","package":"notes.v1","path":"contracts/api/notes/connect/contract.binpb","digest":"sha256:%s","services":[%s]}]}`,
		hex.EncodeToString(sum[:]), services)
	if err := os.WriteFile(filepath.Join(dir, "contracts", "api", "catalog.codefly.json"), []byte(catalog), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A descriptor carries more than its module serves: a protocol the module
// publishes for others to serve (the annotations module's
// TargetAuthorityService, which each owner serves) is declared in it and
// registered on no listener of the module. What a module publishes of its
// methods is what its contract catalog says its endpoints serve, as a
// delivery to the authority reads it; a call to the rest is a call to
// nothing, and no plan is held to it.
func TestWhatAModulePublishesIsWhatItsEndpointsServe(t *testing.T) {
	published := Published{}
	if err := published.PublishedIn("notes", module(t, []string{"Notes", "OwnerProtocol"}, []string{"Notes"})); err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(published["notes"])); !slices.Equal(got, []string{"/notes.v1.Notes/Get"}) {
		t.Errorf("published %v, want the one procedure the catalog says the endpoint serves", got)
	}
	// A module with no catalog serves every service its descriptors declare.
	published = Published{}
	if err := published.PublishedIn("notes", module(t, []string{"Notes", "OwnerProtocol"}, nil)); err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(published["notes"])); !slices.Equal(got, []string{"/notes.v1.Notes/Get", "/notes.v1.OwnerProtocol/Get"}) {
		t.Errorf("with no catalog, published %v", got)
	}
	// A catalog that routes a procedure its contract does not declare is a
	// stale catalog, said and not skipped.
	published = Published{}
	if err := published.PublishedIn("notes", module(t, []string{"Notes"}, []string{"Notes", "Gone"})); err == nil {
		t.Error("a catalog routing a procedure the contract does not declare is read without a word")
	}
}

// The edge answers a page's call to a service it routes for no module with
// a Connect refusal (403 permission_denied, "no module serves …"), where a
// plain request is answered 404. Either is a call nobody is served: it is no
// decision on the person, and satisfies no refusal a plan or a row gives a
// reason for.
func TestAPageCallTheEdgeRoutesNowhereIsUnserved(t *testing.T) {
	c := front(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"permission_denied","message":"no module serves /a.v1.A/Unrouted"}`))
	})
	got := c.As(t, "carol").Do(t, Call{Page: "notes", Procedure: "a.v1.A/Unrouted"})
	if got.Verdict != Unserved {
		t.Fatalf("read as %s, want unserved: %+v", got.Verdict, got)
	}
	for _, want := range []Expect{Admit, Deny("holds no role on notes"), {verdict: Denied, stage: "for holding no role on notes", among: []string{"holds no role on notes"}}} {
		if problem := want.problem(got); problem == "" {
			t.Errorf("a call nobody is served satisfies %+v", want)
		}
	}
}
