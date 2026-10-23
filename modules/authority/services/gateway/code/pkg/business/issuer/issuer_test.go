package issuer_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/core/workcontext/conformance"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// --- the proto moved without moving a byte ------------------------------------

func TestEveryCoreFixturePayloadIsByteIdenticalThroughOurMessage(t *testing.T) {
	fixtures, err := workcontext.Fixtures(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range fixtures {
		payload, _, ok := strings.Cut(f.Token, ".")
		if !ok {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			continue // a fixture built to be undecodable
		}
		ours := &authorityv1.WorkContextV1{}
		if err := proto.Unmarshal(raw, ours); err != nil {
			continue // likewise
		}
		again, err := proto.MarshalOptions{Deterministic: true}.Marshal(ours)
		if err != nil {
			t.Fatal(err)
		}
		theirs := &basev0.WorkContextV1{}
		if err := proto.Unmarshal(raw, theirs); err != nil {
			continue
		}
		canonical, _ := proto.MarshalOptions{Deterministic: true}.Marshal(theirs)
		if string(again) != string(canonical) {
			t.Fatalf("fixture %q: our bytes differ from core's", f.Name)
		}
		checked++
	}
	if checked < 5 {
		t.Fatalf("only %d fixtures round-tripped; the kit should give more", checked)
	}
}

func TestOurDescriptorsNameTheSameFieldsAndNumbersAsCore(t *testing.T) {
	pairs := []struct {
		ours, theirs protoreflect.MessageDescriptor
	}{
		{(&authorityv1.WorkContextV1{}).ProtoReflect().Descriptor(), (&basev0.WorkContextV1{}).ProtoReflect().Descriptor()},
		{(&authorityv1.WorkSealV1{}).ProtoReflect().Descriptor(), (&basev0.WorkSealV1{}).ProtoReflect().Descriptor()},
		{(&authorityv1.WorkOperationBindingV1{}).ProtoReflect().Descriptor(), (&basev0.WorkOperationBindingV1{}).ProtoReflect().Descriptor()},
		{(&authorityv1.WorkScopeV1{}).ProtoReflect().Descriptor(), (&basev0.WorkScopeV1{}).ProtoReflect().Descriptor()},
		{(&authorityv1.WorkActorV1{}).ProtoReflect().Descriptor(), (&basev0.WorkActorV1{}).ProtoReflect().Descriptor()},
		{(&authorityv1.WorkGrantHopV1{}).ProtoReflect().Descriptor(), (&basev0.WorkGrantHopV1{}).ProtoReflect().Descriptor()},
		{(&authorityv1.WorkApproverV1{}).ProtoReflect().Descriptor(), (&basev0.WorkApproverV1{}).ProtoReflect().Descriptor()},
		{(&authorityv1.ApprovalRequiredV1{}).ProtoReflect().Descriptor(), (&basev0.ApprovalRequiredV1{}).ProtoReflect().Descriptor()},
	}
	for _, p := range pairs {
		if p.ours.Fields().Len() != p.theirs.Fields().Len() {
			t.Fatalf("%s: %d fields here, %d in core", p.ours.Name(), p.ours.Fields().Len(), p.theirs.Fields().Len())
		}
		for i := 0; i < p.ours.Fields().Len(); i++ {
			a, b := p.ours.Fields().Get(i), p.theirs.Fields().Get(i)
			if a.Name() != b.Name() || a.Number() != b.Number() || a.Kind() != b.Kind() || a.Cardinality() != b.Cardinality() {
				t.Fatalf("%s: field %d is %s/%d/%s here and %s/%d/%s in core", p.ours.Name(), i, a.Name(), a.Number(), a.Kind(), b.Name(), b.Number(), b.Kind())
			}
		}
	}
}

// --- the kit, against the verifier Check is built on ---------------------------

func TestCoreConformanceKitPassesThroughCheckShapedVerification(t *testing.T) {
	// Check is core's Verifier with our sources. The kit pins its own sources;
	// run it against a verifier built exactly as Check builds one, so a change
	// in how Check wires the verifier fails here before it fails on a laptop.
	settings := conformance.New(time.Now())
	verifier := &workcontext.Verifier{
		Issuer: settings.Issuer, Audience: settings.Audience, Keys: settings.PublicKeys(),
		Revisions: settings.Revisions, Replay: settings.Replay, Seals: settings.Seals, Grants: settings.Grants,
		Now: settings.Now, TrustTheConformanceFixtureKey: settings.TrustTheConformanceFixtureKey,
	}
	conformance.RunWith(t, settings, func(ctx context.Context, token string) error {
		_, err := verifier.Verify(ctx, token)
		return err
	})
}

// --- the shapes ------------------------------------------------------------------

// person signs a fixture person in and returns a context carrying their session,
// as the transport does from the bearer on a call.
func person(t *testing.T, k *testkit.Kit, token string) context.Context {
	t.Helper()
	sess, err := k.State.SignIn(token)
	if err != nil {
		t.Fatal(err)
	}
	return issuer.WithSession(context.Background(), sess.ID)
}

func scopes(sc ...*basev0.WorkScopeV1) []*authorityv1.WorkScopeV1 {
	var out []*authorityv1.WorkScopeV1
	for _, s := range sc {
		out = append(out, &authorityv1.WorkScopeV1{ResourceKind: s.ResourceKind, Actions: s.Actions})
	}
	return out
}

func TestAPersonIsIssuedWhatHerRolesHoldAtTheAudienceAndNoMore(t *testing.T) {
	k := testkit.New(t)
	maya := person(t, k, "fixture-maya")
	out, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents",
	})
	if err != nil {
		t.Fatal(err)
	}
	wc := out.GetContext()
	if wc.GetOwnerPrincipalId() != "maya" || wc.GetTenantId() != "acme" || wc.GetAudience() != "documents" {
		t.Fatalf("context = %v", wc)
	}
	// The viewer reads documents, and reads collections at the kind: which
	// collections is the authority's answer to ListResources, not the token's.
	got := map[string]string{}
	for _, sc := range wc.GetAuthorityScopes() {
		got[sc.GetResourceKind()] = strings.Join(sc.GetActions(), ",")
		if len(sc.GetResourceIds()) != 0 {
			t.Fatalf("the token names no resource: %v", sc)
		}
	}
	if len(got) != 2 || got["documents"] != "read" || got["documents.collection"] != "read" {
		t.Fatalf("viewer scopes = %v", wc.GetAuthorityScopes())
	}
	if wc.GetSeal().GetInstallationId() != "acme/documents" {
		t.Fatalf("sealed to %q", wc.GetSeal().GetInstallationId())
	}
	if wc.GetAttributionTeamIds()[0] != "finance" {
		t.Fatalf("teams = %v", wc.GetAttributionTeamIds())
	}
	// Asking beyond the role is refused, not narrowed silently.
	_, err = k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents",
		Scopes: scopes(testkit.Scope("documents", "write")),
	})
	if !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("beyond the role: %v", err)
	}
	// Asking a subset is honoured.
	remi := person(t, k, "fixture-remi")
	out, err = k.Issuer.Issue(remi, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents",
		Scopes: scopes(testkit.Scope("documents", "read")),
	})
	if err != nil || strings.Join(out.GetContext().GetAuthorityScopes()[0].GetActions(), ",") != "read" {
		t.Fatalf("subset: %v %v", err, out.GetContext().GetAuthorityScopes())
	}
}

func TestAPersonHoldsNothingAtAModuleHerRolesDoNotName(t *testing.T) {
	k := testkit.New(t)
	maya := person(t, k, "fixture-maya")
	_, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "model",
	})
	if !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("model: %v", err)
	}
}

func TestAnUncomposedAudienceIsRefusedByName(t *testing.T) {
	k := testkit.New(t)
	maya := person(t, k, "fixture-maya")
	_, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "modelservice",
	})
	if !errors.Is(err, state.ErrUnknown) || !strings.Contains(err.Error(), `"modelservice" is not composed`) {
		t.Fatalf("the audience typo of this week: %v", err)
	}
}

func TestCheckAcceptsForTheAudienceAndRefusesForAnother(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	maya := person(t, k, "fixture-maya")
	out, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents"})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := k.Issuer.Check(ctx, out.GetToken(), "documents", "")
	if err != nil || checked.GetContext().GetOwnerPrincipalId() != "maya" || checked.GetAuthorizationRevision() == 0 {
		t.Fatalf("check: %v %v", err, checked)
	}
	if _, err := k.Issuer.Check(ctx, out.GetToken(), "model", ""); !errors.Is(err, workcontext.ErrInvalid) {
		t.Fatalf("another audience: %v", err)
	}
	if _, err := k.Issuer.Check(ctx, out.GetToken()+"x", "documents", ""); err == nil {
		t.Fatal("a tampered token verified")
	}
	if _, err := k.Issuer.Check(ctx, out.GetToken(), "", ""); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("a check without an audience: %v", err)
	}
}

func TestAnUninstallRefusesAnOutstandingTokenOnTheNextCheck(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	wiki, _ := k.State.Installation("acme/wiki")
	out, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: wiki.ID}}, Audience: "documents",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, out.GetToken(), "documents", ""); err != nil {
		t.Fatalf("before: %v", err)
	}
	if err := k.State.Revoke(wiki.ID); err != nil {
		t.Fatal(err)
	}
	_, err = k.Issuer.Check(ctx, out.GetToken(), "documents", "")
	if err == nil || !(errors.Is(err, workcontext.ErrRevoked) || errors.Is(err, workcontext.ErrNoSeal)) {
		t.Fatalf("after the uninstall: %v", err)
	}
}

func TestAnInstallationActsForItselfWithinItsRoleAndTheAudiencesCeiling(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	out, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: "acme/wiki"}}, Audience: "documents",
	})
	if err != nil {
		t.Fatal(err)
	}
	wc := out.GetContext()
	if wc.GetOwnerPrincipalId() != "acme/wiki/agent" || wc.GetOwnerPrincipalKind() != "agent" || wc.GetOwnerAgentId() != "wiki" {
		t.Fatalf("owner = %s/%s/%s", wc.GetOwnerPrincipalId(), wc.GetOwnerPrincipalKind(), wc.GetOwnerAgentId())
	}
	if strings.Join(wc.GetAuthorityScopes()[0].GetActions(), ",") != "read" {
		t.Fatalf("viewer role at documents = %v", wc.GetAuthorityScopes())
	}
	if _, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: "acme/nothing"}}, Audience: "documents",
	}); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("unknown installation: %v", err)
	}
}

func TestAPendingInstallationIsIssuedNothing(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	k.State.OnInstall(func(context.Context, state.Installation) error { return errors.New("not yet") })
	if _, err := k.State.ApplyManifest(testkit.Proposals(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.Install(ctx, "acme", "proposals", "viewer", "alex"); err == nil {
		t.Fatal("the install step failed; Install must say so")
	}
	_, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: "acme/proposals"}}, Audience: "documents",
	})
	if !errors.Is(err, workcontext.ErrNoSeal) || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("pending installation: %v", err)
	}
}

func TestAWorkloadIsIssuedItsBindingsHeadlessScopesForTheBindingsAudience(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	cred := k.Credential(t, "documents")
	out, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As:       &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: cred}},
		Audience: "model", OrganizationId: "acme", OperationBindingId: "model",
	})
	if err != nil {
		t.Fatal(err)
	}
	wc := out.GetContext()
	if wc.GetOwnerPrincipalId() != "documents" || wc.GetOwnerPrincipalKind() != "service" || wc.GetAudience() != "model" {
		t.Fatalf("context = %v", wc)
	}
	if wc.GetOperationBinding().GetBindingId() != "acme/documents/model" {
		t.Fatalf("binding = %v", wc.GetOperationBinding())
	}
	if _, err := k.Issuer.Check(ctx, out.GetToken(), "model", ""); err != nil {
		t.Fatalf("model refuses documents' own context: %v", err)
	}
	// The refusals a module hits today, each by name.
	cases := []struct {
		name string
		req  *authorityv1.IssueRequest
		want error
		text string
	}{
		{"undeclared binding", &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: cred}}, Audience: "model", OrganizationId: "acme", OperationBindingId: "tracing"}, workcontext.ErrNoBinding, `no binding "tracing"`},
		{"binding addressed elsewhere", &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: cred}}, Audience: "documents", OrganizationId: "acme", OperationBindingId: "model"}, issuer.ErrRefused, "addressed to model"},
		{"beyond headless", &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: cred}}, Audience: "model", OrganizationId: "acme", OperationBindingId: "model", Scopes: scopes(testkit.Scope("modelservice.profiles", "admin"))}, issuer.ErrRefused, "beyond"},
		{"no organisation", &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: cred}}, Audience: "model", OperationBindingId: "model"}, issuer.ErrRefused, "organization"},
		{"not the launcher's credential", &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: "x.y"}}, Audience: "model", OrganizationId: "acme", OperationBindingId: "model"}, state.ErrForbidden, "workload credential"},
	}
	for _, c := range cases {
		_, err := k.Issuer.Issue(ctx, c.req)
		if !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.text) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
}

// The hop rule: a module hops only on a person's token addressed to it, names
// the binding it exercises, and the child carries what the person holds through
// that binding at its audience, no more.
func TestAChildHopAttenuatesAndNamesItsActorAndItsBinding(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	maya := person(t, k, "fixture-maya")
	parent, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "org-directory", OperationBindingId: "records"})
	if err != nil {
		t.Fatal(err)
	}
	page := &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}
	child, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()}, Actor: page,
		Audience: "records", OperationBindingId: "records", Scopes: scopes(testkit.Scope("records.records", "read")),
	})
	if err != nil {
		t.Fatal(err)
	}
	wc := child.GetContext()
	if wc.GetOwnerPrincipalId() != "maya" || len(wc.GetActorChain()) != 1 || wc.GetActorChain()[0].GetPrincipalId() != "org-directory" || wc.GetOperationBinding().GetBindingId() != "acme/org-directory/records" {
		t.Fatalf("child = owner %s actors %v binding %v", wc.GetOwnerPrincipalId(), wc.GetActorChain(), wc.GetOperationBinding())
	}
	if _, err := k.Issuer.Check(ctx, child.GetToken(), "records", ""); err != nil {
		t.Fatalf("child check: %v", err)
	}
	if _, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()}, Actor: page,
		Audience: "records", OperationBindingId: "records", Scopes: scopes(testkit.Scope("records.records", "write")),
	}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("widening: %v", err)
	}
	if _, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()}, Actor: page, Audience: "records",
	}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("a hop that names no binding: %v", err)
	}
	elsewhere, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: elsewhere.GetToken()}, Actor: page,
		Audience: "records", OperationBindingId: "records", Scopes: scopes(testkit.Scope("records.records", "read")),
	}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("a module hops only on a token addressed to it: %v", err)
	}
	if _, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()}, Audience: "records",
	}); err == nil {
		t.Fatal("a child without an actor")
	}
}

func TestKeysLetAnIndependentVerifierCheckWhatWasIssued(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	keys := k.Issuer.Keys()
	if len(keys.GetKeys()) != 1 || keys.GetKeys()[0].GetAlgorithm() != "Ed25519" || len(keys.GetKeys()[0].GetPublicKey()) != ed25519.PublicKeySize {
		t.Fatalf("keys = %v", keys)
	}
	maya := person(t, k, "fixture-maya")
	out, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents"})
	if err != nil {
		t.Fatal(err)
	}
	// A module's verifier: core's, pinned to what Keys published and to its own audience.
	verifier := &workcontext.Verifier{
		Issuer: keys.GetIssuer(), Audience: "documents",
		Keys:      map[string]ed25519.PublicKey{keys.GetKeys()[0].GetKeyId(): ed25519.PublicKey(keys.GetKeys()[0].GetPublicKey())},
		Revisions: k.State, Seals: k.State, Grants: k.State, Replay: workcontext.NewMemoryReplayStore(), Now: func() time.Time { return k.Now },
	}
	if _, err := verifier.Verify(ctx, out.GetToken()); err != nil {
		t.Fatalf("an independent core verifier refused what we issued: %v", err)
	}
}

func TestTTLIsClampedToTheCeiling(t *testing.T) {
	k := testkit.New(t)
	maya := person(t, k, "fixture-maya")
	out, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents", TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(out.GetExpiresAtUnix(), 0).Sub(k.Now); got < issuer.MaxTTL || got > issuer.MaxTTL+2*time.Second {
		t.Fatalf("ttl = %s", got)
	}
}

func TestAnIssueNamesWhomItIsForAndItsAudience(t *testing.T) {
	k := testkit.New(t)
	if _, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{Audience: "documents"}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("no owner: %v", err)
	}
	if _, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("no audience: %v", err)
	}
}

// A caller that names the binding it exercises need not know where it points:
// the audience is the binding's, for a workload and for a hop.
func TestABindingNamingIssueMayLeaveItsAudienceToTheBinding(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	page := &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}
	own, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Workload{Workload: page}, OrganizationId: "acme", OperationBindingId: "records"})
	if err != nil || own.GetContext().GetAudience() != "records" {
		t.Fatalf("a workload's issue took its audience from the binding: %v %v", own.GetContext().GetAudience(), err)
	}
	maya := person(t, k, "fixture-maya")
	parent, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "org-directory", OperationBindingId: "records"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()}, Actor: page,
		OperationBindingId: "records", Scopes: scopes(testkit.Scope("records.records", "read"))})
	if err != nil || child.GetContext().GetAudience() != "records" {
		t.Fatalf("a hop took its audience from the binding: %v %v", child.GetContext().GetAudience(), err)
	}
	if _, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("a person's issue still names its audience: %v", err)
	}
}

// The local developer's role names no module: it holds every action on every
// kind the audience serves. At a module whose manifest names kinds and not
// actions, an explicit ask is granted as asked and an empty ask is refused by
// name, since "everything" would put no concrete action in the token.
func TestTheDeveloperRoleHoldsWhatEachComposedModuleServes(t *testing.T) {
	k := testkit.New(t)
	held, err := k.State.PersonScopes("dev", "records")
	if err != nil || len(held) != 2 {
		t.Fatalf("dev at records: %v %v", held, err)
	}
	if _, err := k.State.ApplyManifest(state.Manifest{Module: "probe", Principal: "probe", Kind: "module", Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope("probe.items", state.AnyAction)}}); err != nil {
		t.Fatal(err)
	}
	dev := person(t, k, "fixture-dev")
	out, err := k.Issuer.Issue(dev, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "probe", Scopes: scopes(testkit.Scope("probe.items", "run"))})
	if err != nil || out.GetContext().GetAuthorityScopes()[0].GetActions()[0] != "run" {
		t.Fatalf("an explicit ask at a kinds-only module: %v %v", out.GetContext().GetAuthorityScopes(), err)
	}
	if _, err := k.Issuer.Issue(dev, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "probe"}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("an empty ask over undeclared actions: %v", err)
	}
	maya := person(t, k, "fixture-maya")
	if _, err := k.Issuer.Issue(maya, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "probe", Scopes: scopes(testkit.Scope("probe.items", "run"))}); err == nil {
		t.Fatal("a viewer holds nothing at a module her roles do not name")
	}
}
