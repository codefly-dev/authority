package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The setup page at /auth/setup is the run's installation screen: an
// administrator reviews a delivered solution, consents to that exact version,
// chooses its agent role, and grants and revokes its roles. The edge renders
// what the authority answers and posts each change back to it through the
// generated clients with the person's own session; every decision is the
// authority's. Like sign-in, it is a page and plain forms: no script holds a
// credential or calls the authority.

// Installer is the installation interface's changes and reads the page uses.
type Installer interface {
	Install(ctx context.Context, in *installationv1.InstallRequest, opts ...grpc.CallOption) (*installationv1.Installation, error)
	GrantRole(ctx context.Context, in *installationv1.GrantRoleRequest, opts ...grpc.CallOption) (*installationv1.Installation, error)
	RevokeRole(ctx context.Context, in *installationv1.RevokeRoleRequest, opts ...grpc.CallOption) (*installationv1.Installation, error)
	ListRoleGrants(ctx context.Context, in *installationv1.ListRoleGrantsRequest, opts ...grpc.CallOption) (*installationv1.ListRoleGrantsResponse, error)
	List(ctx context.Context, in *installationv1.ListRequest, opts ...grpc.CallOption) (*installationv1.ListResponse, error)
}

// Offers is the local authority's setup read.
type Offers interface {
	ListOffers(ctx context.Context, in *installationv1.ListOffersRequest, opts ...grpc.CallOption) (*installationv1.ListOffersResponse, error)
	ReviewOffer(ctx context.Context, in *installationv1.ReviewRequest, opts ...grpc.CallOption) (*installationv1.ReviewedOffer, error)
}

// setupData is the page's data island (web/src/setup.tsx); the authority's
// messages travel as their protojson.
type setupData struct {
	OrganizationID string            `json:"organizationId"`
	PersonID       string            `json:"personId"`
	People         []setupPerson     `json:"people"`
	Teams          []string          `json:"teams"`
	Offers         json.RawMessage   `json:"offers,omitempty"`
	Installations  json.RawMessage   `json:"installations,omitempty"`
	Review         json.RawMessage   `json:"review,omitempty"`
	Grants         json.RawMessage   `json:"grants,omitempty"`
	OperationID    string            `json:"operationId"`
	Retry          map[string]string `json:"retry,omitempty"`
	Notice         string            `json:"notice,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// setupPerson is a fixture person of the organization, by id and email: no
// sign-in token is on this page.
type setupPerson struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

var setupNotices = map[string]string{
	"installed": "Installed. Grant its roles to the people and teams who use it.",
	"pending":   "Installation pending: the solution has not acknowledged its install step yet.",
	"granted":   "Role granted. It applies from the next call.",
	"revoked":   "Role revoked. What it gave is refused from the next call.",
}

func (e *Edge) setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "the setup page is read with GET and changed with POST")
		return
	}
	bearer, _ := bearerOf(r)
	ctx := metadata.AppendToOutgoingContext(r.Context(), "authorization", "Bearer "+bearer)
	sess, err := e.Sessions.Current(ctx, &sessionv1.CurrentRequest{})
	if bearer == "" || status.Code(err) == codes.Unauthenticated {
		http.Redirect(w, r, "/auth/sign-in?return="+url.QueryEscape("/auth/setup"), http.StatusSeeOther)
		return
	}
	if err != nil {
		refuse(w, http.StatusServiceUnavailable, "the authority did not answer who is signed in: "+status.Convert(err).Message())
		return
	}
	target := r.URL.Query().Get("target")
	var failure string
	var retry map[string]string
	if r.Method == http.MethodPost {
		// A change from a cookie must come from this page, never another site.
		if !sameOrigin(r) {
			refuse(w, http.StatusForbidden, "a setup change must come from this origin")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			refuse(w, http.StatusBadRequest, "the setup form could not be read: "+err.Error())
			return
		}
		target = r.PostForm.Get("target")
		done, err := e.change(ctx, sess, r.PostForm)
		if err == nil {
			http.Redirect(w, r, "/auth/setup?"+url.Values{"target": {target}, "done": {done}}.Encode(), http.StatusSeeOther)
			return
		}
		failure = "The authority refused: " + status.Convert(err).Message()
		if f, ok := err.(formError); ok {
			failure = string(f)
		} else if uncertain(err) && r.PostForm.Get("action") == "install" {
			// Nothing says whether it applied: the exact request is kept, so a
			// retry is the same operation and applies at most once.
			failure = "The authority did not confirm the installation: " + status.Convert(err).Message() + " Retry the same install; it is applied once."
			retry = map[string]string{}
			for key := range r.PostForm {
				retry[key] = r.PostForm.Get(key)
			}
		}
	}
	data, err := e.setupView(ctx, sess, target)
	if err != nil {
		refuse(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	data.Notice = setupNotices[r.URL.Query().Get("done")]
	if failure != "" {
		data.Notice, data.Error, data.Retry = "", failure, retry
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = signInPage.Execute(w, map[string]any{"setup": data})
}

// change applies one posted change and names what happened.
func (e *Edge) change(ctx context.Context, sess *sessionv1.Session, form url.Values) (string, error) {
	org := sess.GetOrganizationId()
	switch form.Get("action") {
	case "install":
		if form.Get("consent") != "on" {
			return "", formError("Consent to the reviewed version before installing.")
		}
		generation, _ := strconv.ParseUint(form.Get("generation"), 10, 64)
		revision, _ := strconv.ParseUint(form.Get("expectedRevision"), 10, 64)
		inst, err := e.Installer.Install(ctx, &installationv1.InstallRequest{OrganizationId: org, Target: form.Get("target"), Role: form.Get("role"), OwnerPersonId: sess.GetPersonId(),
			Approval: &installationv1.ConsentApproval{TargetId: form.Get("targetId"), Generation: generation, ExpectedRevision: revision, Digest: form.Get("digest"), OperationId: form.Get("operationId")}})
		if err != nil {
			return "", err
		}
		if inst.GetStatus() == installationv1.Installation_STATUS_ACTIVE {
			return "installed", nil
		}
		return "pending", nil
	case "grant", "revoke":
		kind, id, _ := strings.Cut(form.Get("subject"), ":")
		person, team := "", ""
		switch kind {
		case "person":
			person = id
		case "team":
			team = id
		default:
			return "", formError("Choose a person or a team.")
		}
		if form.Get("action") == "grant" {
			_, err := e.Installer.GrantRole(ctx, &installationv1.GrantRoleRequest{OrganizationId: org, InstallationId: form.Get("installationId"), Role: form.Get("role"), PersonId: person, TeamId: team})
			return "granted", err
		}
		_, err := e.Installer.RevokeRole(ctx, &installationv1.RevokeRoleRequest{OrganizationId: org, InstallationId: form.Get("installationId"), Role: form.Get("role"), PersonId: person, TeamId: team})
		return "revoked", err
	}
	return "", formError("The setup form names no change.")
}

// formError is the page's own refusal of a form it cannot send.
type formError string

func (f formError) Error() string { return string(f) }

// setupView reads what the page shows, each read through the person's own
// session. A refused read is shown with its reason, not as an empty list.
func (e *Edge) setupView(ctx context.Context, sess *sessionv1.Session, target string) (*setupData, error) {
	org := sess.GetOrganizationId()
	data := &setupData{OrganizationID: org, PersonID: sess.GetPersonId(), People: []setupPerson{}, Teams: []string{}, OperationID: uuid.NewString()}
	people, err := e.Sessions.ListFixturePeople(ctx, &sessionv1.ListFixturePeopleRequest{})
	if err != nil {
		return nil, fmt.Errorf("the authority did not list the organization's people: %s", status.Convert(err).Message())
	}
	for _, p := range people.GetPeople() {
		if p.GetOrganizationId() == org {
			data.People = append(data.People, setupPerson{ID: p.GetPersonId(), Email: p.GetEmail()})
			data.Teams = append(data.Teams, p.GetTeamIds()...)
		}
	}
	slices.Sort(data.Teams)
	data.Teams = slices.Compact(data.Teams)
	offers, err := e.Offers.ListOffers(ctx, &installationv1.ListOffersRequest{OrganizationId: org})
	if err != nil {
		data.Error = "The authority refused the installations of " + org + ": " + status.Convert(err).Message()
		return data, nil
	}
	installed, err := e.Installer.List(ctx, &installationv1.ListRequest{OrganizationId: org})
	if err != nil {
		data.Error = "The authority refused the installations of " + org + ": " + status.Convert(err).Message()
		return data, nil
	}
	data.Offers, data.Installations = wire(offers), wire(installed)
	if target == "" {
		return data, nil
	}
	review, err := e.Offers.ReviewOffer(ctx, &installationv1.ReviewRequest{OrganizationId: org, Target: target})
	if err != nil {
		data.Error = "The authority refused the review of " + target + ": " + status.Convert(err).Message()
		return data, nil
	}
	data.Review = wire(review)
	if inst := review.GetInstallation(); inst != nil {
		grants, err := e.Installer.ListRoleGrants(ctx, &installationv1.ListRoleGrantsRequest{OrganizationId: org, InstallationId: inst.GetId()})
		if err != nil {
			data.Error = "The authority refused the role grants of " + target + ": " + status.Convert(err).Message()
			return data, nil
		}
		data.Grants = wire(grants)
	}
	return data, nil
}

// wire is a message as the page reads it: protojson, field names as declared.
func wire(m proto.Message) json.RawMessage {
	raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		return nil
	}
	return raw
}

// uncertain is a failure that does not say whether the change applied.
func uncertain(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Unknown, codes.Internal, codes.Canceled:
		return true
	}
	return false
}
