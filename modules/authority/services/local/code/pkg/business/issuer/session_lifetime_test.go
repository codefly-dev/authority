package issuer_test

import (
	"context"
	"testing"
	"time"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

func TestEndingSessionRefusesPreviouslyIssuedWork(t *testing.T) {
	k := testkit.New(t)
	sess, err := k.State.SignIn("fixture-maya")
	if err != nil {
		t.Fatal(err)
	}
	ctx := issuer.WithSession(context.Background(), sess.ID)
	out, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(context.Background(), out.GetToken(), "records", ""); err != nil {
		t.Fatal(err)
	}
	if err := k.State.EndSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(context.Background(), out.GetToken(), "records", ""); err == nil {
		t.Fatal("issued work remains valid after its session ended")
	}
}

func TestIssuedWorkEndsNoLaterThanItsSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	k := testkit.NewWithClock(t, func() time.Time { return now })
	sess, err := k.State.SignIn("fixture-maya")
	if err != nil {
		t.Fatal(err)
	}
	now = sess.ExpiresAt.Add(-time.Second)
	out, err := k.Issuer.Issue(issuer.WithSession(context.Background(), sess.ID), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records",
	})
	if err != nil {
		t.Fatal(err)
	}
	if expiry := time.Unix(out.GetContext().GetExpiresAtUnix(), 0); expiry.After(sess.ExpiresAt) {
		t.Fatalf("capability expires at %s, after session deadline %s", expiry, sess.ExpiresAt)
	}
}

func TestSigningOutPreservesAnotherSessionForTheSamePerson(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	issue := func() (string, string) {
		t.Helper()
		session, err := k.State.SignIn("fixture-maya")
		if err != nil {
			t.Fatal(err)
		}
		out, err := k.Issuer.Issue(issuer.WithSession(ctx, session.ID), &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records",
		})
		if err != nil {
			t.Fatal(err)
		}
		return session.ID, out.GetToken()
	}
	first, firstToken := issue()
	_, otherToken := issue()
	if err := k.State.EndSession(first); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, firstToken, "records", ""); err == nil {
		t.Fatal("ended session still admitted")
	}
	if _, err := k.Issuer.Check(ctx, otherToken, "records", ""); err != nil {
		t.Fatalf("independent session refused: %v", err)
	}
}

func TestEndingSessionAlsoRevokesDerivedWork(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	sess, err := k.State.SignIn("fixture-maya")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := k.Issuer.Issue(issuer.WithSession(ctx, sess.ID), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "org-directory", OperationBindingId: "records",
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As:    &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()},
		Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}, Audience: "records", OperationBindingId: "records",
		Scopes: scopes(testkit.Scope("records.records", "read")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, child.GetToken(), "records", ""); err != nil {
		t.Fatal(err)
	}
	if err := k.State.EndSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, child.GetToken(), "records", ""); err == nil {
		t.Fatal("child of ended session still admitted")
	}
}
