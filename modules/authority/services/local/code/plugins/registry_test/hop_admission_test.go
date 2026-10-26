package registry_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	"gateway/plugins/authority"
)

// Review r4 B1', under the playground's identity. The playground run starts
// the hop as authority/hop in workspace authority-playground with its own
// service-scoped hop-signing/SEED and its projected workload credential, and
// hands the local authority neither. The authority used to derive the key from
// that seed, so this run published no admission key and the console refused
// every call (keys_unavailable). Now the hop presents its public key over the
// wire under its workload credential, Keys publishes it, and a stamp the hop
// signs is admitted by the published key alone (the check every module's
// verifier makes first), while one signed by any other key is not.
//
// The module side's verifier (libraries/hop/go) links the authority-client
// bindings of the same protos, which cannot share a binary with this
// service's own, so it is driven from Keys in its own module
// (TestAVerifierThatReadBeforeTheHopRegisteredLearnsItsKeyWithinKeyRetry) and
// in the playground run; here the wire is this service's generated client.
func TestUnderThePlaygroundsIdentityTheHopsRegisteredKeyAdmitsItsStamps(t *testing.T) {
	k := testkit.New(t)
	client := authorityv1.NewAuthorityServiceClient(serveAuthority(t, k))
	ctx := context.Background()

	// The hop's process, as the playground run starts it.
	seed := sha256.Sum256([]byte("the playground hop"))
	projected := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(projected, []byte(k.HopCredential(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(resources.WorkspacePrefix, "authority-playground")
	t.Setenv(resources.EnvironmentPrefix, "local")
	t.Setenv(resources.ModulePrefix, "authority")
	t.Setenv(resources.ServicePrefix, "hop")
	t.Setenv(resources.ServiceSecretConfigurationPrefix+"__AUTHORITY__HOP__HOP_SIGNING__SEED", hex.EncodeToString(seed[:]))
	delivered, err := codefly.For(ctx).Secret("hop-signing", "SEED")
	if err != nil {
		t.Fatalf("the hop reads its own seed under the playground's identity: %v", err)
	}
	signer, err := stamp.NewSigner(delivered)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := client.Keys(ctx, &authorityv1.KeysRequest{})
	if err != nil || len(keys.GetAdmissionKeys()) != 0 {
		t.Fatalf("before the hop registered Keys publishes %v: %v", keys.GetAdmissionKeys(), err)
	}

	// The hop registers, presenting its public half and its credential.
	credential, err := os.ReadFile(projected)
	if err != nil {
		t.Fatal(err)
	}
	id, public := signer.Admission()
	register := func(credential string, public []byte) (*authorityv1.RegisterAdmissionKeyResponse, error) {
		return client.RegisterAdmissionKey(ctx, &authorityv1.RegisterAdmissionKeyRequest{
			Actor: &authorityv1.WorkloadCredential{Credential: credential}, PublicKey: public})
	}
	first, err := register(string(credential), public)
	if err != nil || first.GetKey().GetKeyId() != id || first.GetExpiresAtUnix() <= time.Now().Unix() {
		t.Fatalf("the hop's registration: %v %v", first, err)
	}
	// A restart registers again: still one key, renewed.
	again, err := register(string(credential), public)
	if err != nil || again.GetExpiresAtUnix() < first.GetExpiresAtUnix() {
		t.Fatalf("the hop's re-registration: %v %v", again, err)
	}

	keys, err = client.Keys(ctx, &authorityv1.KeysRequest{})
	if err != nil || len(keys.GetAdmissionKeys()) != 1 {
		t.Fatalf("after the hop registered Keys publishes %v: %v", keys.GetAdmissionKeys(), err)
	}
	var published []string
	for _, key := range keys.GetAdmissionKeys() {
		if key.GetPurpose() != stamp.Purpose {
			t.Fatalf("an admission key with purpose %q", key.GetPurpose())
		}
		published = append(published, hex.EncodeToString(key.GetPublicKey()))
	}

	issued, err := k.PersonIssue(t, "maya", "documents")
	if err != nil {
		t.Fatal(err)
	}
	// The run's clock: the testkit's starts at a fixed instant.
	now := time.Unix(issued.GetContext().GetNotBeforeUnix(), 0)
	stamped := func(by *stamp.Signer) metadata.MD {
		proof, err := by.Sign(issued.GetToken(), "/test.Service/Read", "documents", now, issued.GetExpiresAtUnix())
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(issued.GetToken()))
		return metadata.Pairs("x-codefly-work-context", issued.GetToken(), "x-codefly-hop-context", hex.EncodeToString(sum[:]), "x-codefly-hop-proof", proof)
	}
	md := stamped(signer)
	key := stamp.SignedBy(md, published)
	if key == "" {
		t.Fatal("a genuine stamp is signed by no published key")
	}
	if _, err := stamp.Check(md, key, "/test.Service/Read", "documents", now); err != nil {
		t.Fatalf("a genuine stamp under the published key: %v", err)
	}
	other := sha256.Sum256([]byte("not the hop"))
	impostor, _ := stamp.NewSigner(hex.EncodeToString(other[:]))
	if stamp.SignedBy(stamped(impostor), published) != "" {
		t.Fatal("a stamp by an unregistered key is signed by a published one")
	}

	// Another workload presenting its key is refused by name, and publishes nothing.
	_, impostorKey := impostor.Admission()
	if _, err := register(k.Credential(t, "documents"), impostorKey); status.Code(err) != codes.PermissionDenied ||
		!strings.Contains(err.Error(), "the caller is documents/documents, not the hop (authority/hop)") {
		t.Fatalf("a module registered an admission key: %v", err)
	}
	if keys, _ := client.Keys(ctx, &authorityv1.KeysRequest{}); len(keys.GetAdmissionKeys()) != 1 {
		t.Fatalf("a refused registration changed Keys: %v", keys.GetAdmissionKeys())
	}
}

func serveAuthority(t *testing.T, k *testkit.Kit) *grpc.ClientConn {
	t.Helper()
	server := grpc.NewServer()
	(&authority.Plugin{Issuer: k.Issuer}).RegisterGRPC(server)
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
