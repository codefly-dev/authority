package authority_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gateway/pkg/business/testkit"
	authorityplugin "gateway/plugins/authority"
)

// A module with no generated client of its own (a Python service) asks the
// authority over HTTP: Issue and Check are the gRPC methods transcoded, the
// Authorization header carried as the bearer, so a person's session and a
// workload's credential each issue what they do over gRPC.
func TestIssueAndCheckAreServedOverHTTP(t *testing.T) {
	k := testkit.New(t)
	plugin := &authorityplugin.Plugin{Issuer: k.Issuer}
	server := grpc.NewServer()
	plugin.RegisterGRPC(server)
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	mux := runtime.NewServeMux()
	if err := plugin.RegisterREST(context.Background(), mux, "passthrough:///bufconn", []grpc.DialOption{
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}); err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(mux)
	t.Cleanup(web.Close)
	post := func(path, bearer, body string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, web.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var answer map[string]any
		_ = json.NewDecoder(res.Body).Decode(&answer)
		return res.StatusCode, answer
	}

	// A workload issues its own context for a binding, as the scorer does for the judge.
	credential := k.Credential(t, "documents")
	status, issued := post("/v1/authority:issue", "", `{"workload":{"credential":`+jsonString(credential)+`},"organizationId":"acme","operationBindingId":"model"}`)
	if status != http.StatusOK || issued["token"] == "" || issued["expiresAtUnix"] == nil {
		t.Fatalf("workload issue answered %d: %v", status, issued)
	}
	// Its token checks at the binding's audience.
	status, checked := post("/v1/authority:check", "", `{"token":`+jsonString(issued["token"].(string))+`,"audience":"model"}`)
	if status != http.StatusOK || checked["context"] == nil {
		t.Fatalf("check answered %d: %v", status, checked)
	}
	// A person issues with her session as the bearer.
	sess, err := k.State.SignIn("fixture-remi")
	if err != nil {
		t.Fatal(err)
	}
	status, person := post("/v1/authority:issue", sess.ID, `{"person":{},"audience":"documents"}`)
	if status != http.StatusOK || person["token"] == "" {
		t.Fatalf("person issue answered %d: %v", status, person)
	}
	// A refusal keeps its code: a person's issue with no session is refused as
	// it is over gRPC (the gateway answers it forbidden), never answered.
	if status, answer := post("/v1/authority:issue", "", `{"person":{},"audience":"documents"}`); status != http.StatusForbidden || answer["token"] != nil {
		t.Fatalf("an issue with no session answered %d: %v", status, answer)
	}
	// The key set is still served.
	res, err := http.Get(web.URL + authorityplugin.KeySetPath)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("key set: %v %v", res, err)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
