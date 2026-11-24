// Package access is the host side of codefly.dev/access: grants on one
// collection, one document or one exact version, and the decision that
// combines them with what a Work Context's role scopes already reach. Both
// hosts serve the interface through this package: the local authority over the
// in-memory store, accounts over its own record shares, each behind Store.
//
// The module serving a kind asks. It forwards the caller's Work Context and
// attests where the resource sits (Placement); nothing but the verified Work
// Context says who is asking. Verification, the serving-module rule and every
// read of identity are the authority core's (authority.Service.AccessCaller);
// this package verifies no token itself.
package access

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/google/uuid"
)

// The bounds of one request.
const (
	// MaxAncestors is the most collections a placement names above a resource.
	MaxAncestors = 8
	// MaxBatch is the most placements one CheckBatch decides.
	MaxBatch = 1000
	// MaxActions is the most actions one grant gives.
	MaxActions = 16
	// DefaultPageSize and MaxPageSize bound a ListViewerGrants page.
	DefaultPageSize = 100
	MaxPageSize     = 1000
	// ShareAction is the action a Work Context holds on a kind to grant,
	// revoke and list grants on its resources; AdminAction on the resource
	// or a collection above it lets a caller who does not own it do so.
	ShareAction = "share"
	AdminAction = "admin"
)

// Grantable are the actions a grant may give, and the only ones: reading,
// writing and, named explicitly, sharing. Deleting is never granted, and the
// wildcard never is: a grant names what it gives.
var Grantable = []string{"read", ShareAction, "write"}

// StaleRevision is the reason of ErrStale, as the wire carries it.
const StaleRevision = "stale_revision"

// ErrStale is answered when what a caller holds was read at a state of the
// grants that no longer stands: a page token from before a grant changed, an
// expiry passed or the viewer's teams moved. A transport reports it ABORTED
// with the reason StaleRevision; the caller starts again.
var ErrStale = errors.New(StaleRevision)

// NothingRevoked is the reason a Revoke that removed no grant is refused by.
const NothingRevoked = "nothing was revoked"

// Authority is what the service reads of the authority core: the verified
// caller and the existence of a grant's subject. *authority.Service is one.
type Authority interface {
	AccessCaller(ctx context.Context, token string, actor authority.Workload, kinds []string) (authority.AccessCaller, error)
	AccessSubjectExists(ctx context.Context, org string, subject domain.AccessSubject) (bool, error)
}

// Config is what a host injects.
type Config struct {
	// Clock is now, for expiry; required (a host passes its authority's).
	Clock func() time.Time
	// NewID names a new grant; nil means a random UUID.
	NewID func() string
	// InstalledContentRead says whether a verified Work Context is an
	// installed-content read, the host's own class of binding under which the
	// installed module is no subject of the decision and the owner alone
	// must hold the resource. The host answers true only for a binding of
	// that class it resolved live now, and an error when the binding names
	// the class and is not live: the question is then refused. nil: the host
	// has no such class, and every chain is ordinary delegation.
	InstalledContentRead func(ctx context.Context, wc *basev0.WorkContextV1) (bool, error)
	// MinRevisions says this host serves revision minimums: its store keeps
	// the order Tx.AccessSequence answers, over every change that can alter a
	// decision, and what Authority reads is at least as new as the store
	// snapshot a decision is made in. False, a request that names a minimum
	// or asks for the newest state is refused, never ignored.
	MinRevisions bool
	// Primary is the store holding the newest committed state, when the store
	// given to New may lag it (a replica): every change is written to it, a
	// request for the newest state reads it, and so does a read whose
	// minimum the lagging store has not reached within LagWait. nil: the
	// store given to New is that store.
	Primary Store
	// LagWait is how long a read waits for a lagging store to reach its
	// minimum before reading Primary; zero is DefaultLagWait.
	LagWait time.Duration
}

// Service answers the access interface over one authority and one store.
type Service struct {
	authority Authority
	store     Store
	cfg       Config
}

// New builds the service.
func New(auth Authority, store Store, cfg Config) (*Service, error) {
	if auth == nil || store == nil || cfg.Clock == nil {
		return nil, errors.New("access: an authority, a store and a clock are required")
	}
	if cfg.NewID == nil {
		cfg.NewID = uuid.NewString
	}
	return &Service{authority: auth, store: store, cfg: cfg}, nil
}

// Target is the reference a grant is on.
type Target struct {
	Kind, ResourceID, Version string
}

// GrantRequest makes or refreshes one grant.
type GrantRequest struct {
	Token     string
	Actor     authority.Workload
	Target    Target
	Placement Placement
	Subject   domain.AccessSubject
	Actions   []string
	// ExpiresAt ends the grant by itself; zero stands until revoked.
	ExpiresAt time.Time
}

// RevokeRequest ends one grant; ListRequest lists a reference's.
type RevokeRequest struct {
	Token     string
	Actor     authority.Workload
	Target    Target
	Placement Placement
	Subject   domain.AccessSubject
}

// ListRequest asks for the grants on one reference, every version of it.
type ListRequest struct {
	Token     string
	Actor     authority.Workload
	Target    Target
	Placement Placement
}

// CheckRequest asks decisions for one action, all computed at one state.
// MinRevision is the earliest state they may be computed at;
// ItemMinRevisions names one more minimum per placement, none or exactly one
// for each (a zero one names none); Head asks for the newest committed state.
type CheckRequest struct {
	Token            string
	Actor            authority.Workload
	Action           string
	Placements       []Placement
	MinRevision      Minimum
	ItemMinRevisions []Minimum
	Head             bool
}

// ViewerGrantsRequest pages the viewer's direct grants.
type ViewerGrantsRequest struct {
	Token       string
	Actor       authority.Workload
	Kinds       []string
	Action      string
	PageSize    int
	PageToken   string
	MinRevision Minimum
}

// ViewerGrants is one page.
type ViewerGrants struct {
	Resources  []Target
	NextPage   string
	Revision   Revision
	ValidUntil time.Time
}

// Grant gives a subject actions on a reference, or refreshes the grant the
// subject holds there. The caller holds share and every granted action on the
// target's kind, and owns the target or administers it.
func (s *Service) Grant(ctx context.Context, r GrantRequest) (domain.AccessGrant, Revision, error) {
	if err := validSubject(r.Subject); err != nil {
		return domain.AccessGrant{}, Revision{}, err
	}
	actions, err := validActions(r.Actions)
	if err != nil {
		return domain.AccessGrant{}, Revision{}, err
	}
	caller, full, err := s.manager(ctx, r.Token, r.Actor, r.Target, r.Placement)
	if err != nil {
		return domain.AccessGrant{}, Revision{}, err
	}
	for _, action := range actions {
		if !scope.HoldsAction(caller.Effective, r.Target.Kind, action) {
			return domain.AccessGrant{}, Revision{}, domain.Refuse("the capability holds no %s:%s, so it grants none", r.Target.Kind, action)
		}
	}
	now := s.cfg.Clock()
	if !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
		return domain.AccessGrant{}, Revision{}, domain.Malformed("a grant expires in the future, or never")
	}
	// One sentence whether the subject is absent or another organization's.
	exists, err := s.authority.AccessSubjectExists(ctx, caller.Organization, r.Subject)
	if err != nil {
		return domain.AccessGrant{}, Revision{}, err
	}
	if !exists {
		return domain.AccessGrant{}, Revision{}, domain.Refuse("the subject is not a member, a team or an active installation of %s", caller.Organization)
	}
	grant := domain.AccessGrant{AccessKey: key(caller.Organization, r.Target, r.Subject), Actions: actions,
		ExpiresAt: r.ExpiresAt, GrantedBy: caller.Claims.GetOwnerPrincipalId()}
	revision := Revision{Organization: caller.Organization}
	err = s.writer().WriteAccess(ctx, func(tx Tx) error {
		if !full {
			// A grantee shares on only what a share gives them, and for no
			// longer: nobody grants what they do not hold.
			until, err := s.resharer(tx, caller, r.Target, r.Placement, now, actions...)
			if err != nil {
				return err
			}
			if !until.IsZero() && (r.ExpiresAt.IsZero() || r.ExpiresAt.After(until)) {
				return domain.Refuse("a share made on from a share that expires ends no later than it does")
			}
		}
		grant.ID, grant.CreatedAt = s.cfg.NewID(), now
		standing, err := tx.AccessGrant(grant.AccessKey)
		switch {
		case err == nil:
			grant.ID, grant.CreatedAt = standing.ID, standing.CreatedAt
		case !errors.Is(err, domain.ErrNotFound):
			return err
		}
		if err := tx.PutAccessGrant(grant); err != nil {
			return err
		}
		revision.Sequence, err = tx.AccessSequence(caller.Organization)
		return err
	})
	if err != nil {
		return domain.AccessGrant{}, Revision{}, err
	}
	return grant, revision, nil
}

// Revoke ends the grant a subject holds on a reference, for the callers Grant
// admits. A grant that is absent or expired is refused NotFound
// (NothingRevoked) once the caller was authorized, so a caller who may not
// revoke learns nothing of whether it exists.
func (s *Service) Revoke(ctx context.Context, r RevokeRequest) (domain.AccessGrant, Revision, error) {
	if err := validSubject(r.Subject); err != nil {
		return domain.AccessGrant{}, Revision{}, err
	}
	caller, full, err := s.manager(ctx, r.Token, r.Actor, r.Target, r.Placement)
	if err != nil {
		return domain.AccessGrant{}, Revision{}, err
	}
	var revoked domain.AccessGrant
	revision := Revision{Organization: caller.Organization}
	err = s.writer().WriteAccess(ctx, func(tx Tx) error {
		if !full {
			if _, err := s.resharer(tx, caller, r.Target, r.Placement, s.cfg.Clock()); err != nil {
				return err
			}
		}
		k := key(caller.Organization, r.Target, r.Subject)
		standing, err := tx.AccessGrant(k)
		if errors.Is(err, domain.ErrNotFound) || (err == nil && !standing.Live(s.cfg.Clock())) {
			return domain.Missing(NothingRevoked)
		}
		if err != nil {
			return err
		}
		if !full && standing.GrantedBy != caller.Claims.GetOwnerPrincipalId() {
			// A grantee ends the shares they made and no other: one made by
			// somebody else is nothing of theirs to revoke, and is answered
			// as an absent one is.
			return domain.Missing(NothingRevoked)
		}
		existed, err := tx.DeleteAccessGrant(k)
		if err != nil {
			return err
		}
		if !existed {
			return domain.Missing(NothingRevoked)
		}
		revoked = standing
		revision.Sequence, err = tx.AccessSequence(caller.Organization)
		return err
	})
	if err != nil {
		return domain.AccessGrant{}, Revision{}, err
	}
	return revoked, revision, nil
}

// ListGrants answers the live grants on a reference, every version of it, for
// the callers Grant admits, read at the newest state: a grant just made is
// listed.
func (s *Service) ListGrants(ctx context.Context, r ListRequest) ([]domain.AccessGrant, Revision, error) {
	caller, full, err := s.manager(ctx, r.Token, r.Actor, r.Target, r.Placement)
	if err != nil {
		return nil, Revision{}, err
	}
	if !full {
		// A grantee, share or not, never reads who else holds the reference.
		return nil, Revision{}, errNotManager
	}
	var grants []domain.AccessGrant
	revision, err := s.view(ctx, caller.Organization, true, nil, func(tx Tx) (err error) {
		grants, err = tx.AccessGrantsOn(caller.Organization, []Ref{{Kind: r.Target.Kind, ResourceID: r.Target.ResourceID}}, s.cfg.Clock())
		return err
	})
	if err != nil {
		return nil, Revision{}, err
	}
	return grants, revision, nil
}

// errNotManager refuses a caller who may not grant, revoke or list on a
// reference. It names no resource and is the same whatever grants exist.
var errNotManager = domain.Refuse("the caller neither owns what it shares nor administers it, and holds no share of it")

// manager verifies the caller of Grant, Revoke and ListGrants and holds it to
// what they share: share on the target's kind. full says the caller manages
// the reference outright: it is the target's owner as the module attests it,
// or holds admin on the target or a collection above it. A caller that is
// not is still to be held to resharer, in the transaction that writes.
func (s *Service) manager(ctx context.Context, token string, actor authority.Workload, target Target, p Placement) (caller authority.AccessCaller, full bool, err error) {
	if err := validPlacement(p); err != nil {
		return authority.AccessCaller{}, false, err
	}
	if target.Kind != p.Resource.Kind || target.ResourceID != p.Resource.ResourceID {
		return authority.AccessCaller{}, false, domain.Malformed("the placement places the target: its resource is the reference granted")
	}
	if err := validVersion(target.Version); err != nil {
		return authority.AccessCaller{}, false, err
	}
	caller, err = s.authority.AccessCaller(ctx, token, actor, kindsOf(p))
	if err != nil {
		return authority.AccessCaller{}, false, err
	}
	if !scope.HoldsAction(caller.Effective, target.Kind, ShareAction) {
		return authority.AccessCaller{}, false, domain.Refuse("the capability holds no %s:%s", target.Kind, ShareAction)
	}
	owns := p.Resource.Owner != "" && p.Resource.Owner == caller.Claims.GetOwnerPrincipalId()
	administers := slices.ContainsFunc(append([]Node{p.Resource}, p.Ancestors...), func(n Node) bool {
		return Selects(caller.Effective, n, AdminAction)
	})
	return caller, owns || administers, nil
}

// resharer holds a caller who neither owns nor administers the target to the
// shares made to it: live grants must give share, and every one of actions,
// on exactly the reference targeted (a grant pinned to a version shares that
// version on, never the document), to the capability's owner and to every
// actor of its chain, as a decision requires. It answers when the earliest of
// those grants ends, zero when none does. It reads in the transaction that
// writes, so a share revoked before the write shares nothing on.
func (s *Service) resharer(tx Tx, caller authority.AccessCaller, target Target, p Placement, now time.Time, actions ...string) (time.Time, error) {
	p.Resource.Version = target.Version
	refs := make([]Ref, 0, 1+len(p.Ancestors))
	for _, n := range append([]Node{p.Resource}, p.Ancestors...) {
		refs = append(refs, Ref{Kind: n.Kind, ResourceID: n.ResourceID})
	}
	grants, err := tx.AccessGrantsOn(caller.Organization, refs, now)
	if err != nil {
		return time.Time{}, err
	}
	var until time.Time
	for _, action := range append([]string{ShareAction}, actions...) {
		for _, required := range append([]authority.AccessParty{caller.Owner}, caller.Actors...) {
			// The party holds the action until the last of its grants ends.
			held, forever := false, false
			var last time.Time
			for _, g := range grants {
				if !g.Live(now) || !g.Gives(action) || !slices.Contains(required.Subjects, g.Subject) {
					continue
				}
				if _, ok := covers(g, p); ok {
					held = true
					forever = forever || g.ExpiresAt.IsZero()
					if g.ExpiresAt.After(last) {
						last = g.ExpiresAt
					}
				}
			}
			if held && !forever {
				until = earliest(until, last)
			}
			// An actor that owns the place (the installation whose collection
			// it is) holds it without a grant, as it does in a decision.
			owns := required.Principal != caller.Owner.Principal && required.Owns != "" &&
				slices.ContainsFunc(append([]Node{p.Resource}, p.Ancestors...), func(n Node) bool { return n.Owner == required.Owns })
			if !held && !owns {
				if action == ShareAction {
					return time.Time{}, errNotManager
				}
				return time.Time{}, domain.Refuse("the caller's share gives no %s, so it shares none on", action)
			}
		}
	}
	return until, nil
}

// Check decides one action on each placement against one snapshot of the
// grants, in request order, and answers the revision of that snapshot: at or
// past every minimum the request names. A capability that does not hold the
// action on a placement's kind refuses the whole request, naming the kind and
// the action.
func (s *Service) Check(ctx context.Context, r CheckRequest) ([]Decision, Revision, error) {
	if err := s.served(r.Head, append([]Minimum{r.MinRevision}, r.ItemMinRevisions...)...); err != nil {
		return nil, Revision{}, err
	}
	if len(r.ItemMinRevisions) != 0 && len(r.ItemMinRevisions) != len(r.Placements) {
		return nil, Revision{}, domain.Malformed("a check names a minimum revision for every placement or for none: %d for %d", len(r.ItemMinRevisions), len(r.Placements))
	}
	if r.Action == "" {
		return nil, Revision{}, domain.Malformed("a check names an action")
	}
	if len(r.Placements) == 0 || len(r.Placements) > MaxBatch {
		return nil, Revision{}, domain.Malformed("a check decides between 1 and %d placements, not %d", MaxBatch, len(r.Placements))
	}
	var kinds []string
	var refs []Ref
	for _, p := range r.Placements {
		if err := validPlacement(p); err != nil {
			return nil, Revision{}, err
		}
		kinds = append(kinds, kindsOf(p)...)
		for _, n := range append([]Node{p.Resource}, p.Ancestors...) {
			refs = append(refs, Ref{Kind: n.Kind, ResourceID: n.ResourceID})
		}
	}
	slices.Sort(kinds)
	kinds = slices.Compact(kinds)
	caller, err := s.authority.AccessCaller(ctx, r.Token, r.Actor, kinds)
	if err != nil {
		return nil, Revision{}, err
	}
	for _, p := range r.Placements {
		if err := Ceiling(caller.Effective, p.Resource.Kind, r.Action); err != nil {
			return nil, Revision{}, err
		}
	}
	ownerAlone := false
	if s.cfg.InstalledContentRead != nil {
		if ownerAlone, err = s.cfg.InstalledContentRead(ctx, caller.Claims); err != nil {
			return nil, Revision{}, err
		}
	}
	mins, err := s.minimums(caller.Organization, append([]Minimum{r.MinRevision}, r.ItemMinRevisions...)...)
	if err != nil {
		return nil, Revision{}, err
	}
	now := s.cfg.Clock()
	var grants []domain.AccessGrant
	revision, err := s.view(ctx, caller.Organization, r.Head, mins, func(tx Tx) (err error) {
		grants, err = tx.AccessGrantsOn(caller.Organization, refs, now)
		return err
	})
	if err != nil {
		return nil, Revision{}, err
	}
	q := Question{Action: r.Action, Effective: caller.Effective, Owner: party(caller.Owner), OwnerAlone: ownerAlone,
		Grants: grants, Now: now, Expires: caller.ExpiresAt}
	for _, a := range caller.Actors {
		q.Actors = append(q.Actors, party(a))
	}
	out := make([]Decision, len(r.Placements))
	for i, p := range r.Placements {
		q.Placement = p
		if out[i], err = Decide(q); err != nil {
			return nil, Revision{}, err
		}
	}
	// Recheck after the grants were read: a revocation of the capability
	// itself between the two releases no decision made before it.
	if _, err := s.authority.AccessCaller(ctx, r.Token, r.Actor, kinds); err != nil {
		return nil, Revision{}, err
	}
	return out, revision, nil
}

// ListViewerGrants pages the references the capability's owner is granted
// action on directly, of kinds, ordered by kind, id and version. It answers
// grants, not decisions: the actors of the chain are not consulted, and the
// module checks what it serves. A page token binds the viewer's subjects, the
// kinds, the action, the grants' revision and their next expiry; any of them
// moving refuses it ErrStale.
func (s *Service) ListViewerGrants(ctx context.Context, r ViewerGrantsRequest) (ViewerGrants, error) {
	if err := s.served(false, r.MinRevision); err != nil {
		return ViewerGrants{}, err
	}
	if r.Action == "" || len(r.Kinds) == 0 {
		return ViewerGrants{}, domain.Malformed("a viewer's grants are asked for an action on at least one kind")
	}
	if r.PageSize < 0 {
		return ViewerGrants{}, domain.Malformed("a page size is not negative")
	}
	size := r.PageSize
	if size == 0 {
		size = DefaultPageSize
	}
	size = min(size, MaxPageSize)
	kinds := slices.Clone(r.Kinds)
	slices.Sort(kinds)
	kinds = slices.Compact(kinds)
	if slices.Contains(kinds, "") {
		return ViewerGrants{}, domain.Malformed("a resource kind is not empty")
	}
	caller, err := s.authority.AccessCaller(ctx, r.Token, r.Actor, kinds)
	if err != nil {
		return ViewerGrants{}, err
	}
	for _, kind := range kinds {
		if err := Ceiling(caller.Effective, kind, r.Action); err != nil {
			return ViewerGrants{}, err
		}
	}
	mins, err := s.minimums(caller.Organization, r.MinRevision)
	if err != nil {
		return ViewerGrants{}, err
	}
	now := s.cfg.Clock()
	var held []domain.AccessGrant
	var generation uint64
	out := ViewerGrants{ValidUntil: caller.ExpiresAt}
	out.Revision, err = s.view(ctx, caller.Organization, false, mins, func(tx Tx) (err error) {
		if held, err = tx.AccessGrantsTo(caller.Organization, caller.Owner.Subjects, now); err != nil {
			return err
		}
		generation, err = tx.AccessRevision(caller.Organization)
		return err
	})
	if err != nil {
		return ViewerGrants{}, err
	}
	var all []Target
	var expiry time.Time
	for _, g := range held {
		if !slices.Contains(kinds, g.Kind) || !g.Gives(r.Action) {
			continue
		}
		all = append(all, Target{Kind: g.Kind, ResourceID: g.ResourceID, Version: g.Version})
		expiry = earliest(expiry, g.ExpiresAt)
	}
	slices.SortFunc(all, func(a, b Target) int {
		return strings.Compare(a.Kind+"\x00"+a.ResourceID+"\x00"+a.Version, b.Kind+"\x00"+b.ResourceID+"\x00"+b.Version)
	})
	all = slices.Compact(all)
	out.ValidUntil = earliest(out.ValidUntil, expiry)
	binding := pageToken{Digest: viewerDigest(caller, kinds, r.Action), Revision: generation}
	if !expiry.IsZero() {
		binding.Expiry = expiry.UnixNano()
	}
	from := 0
	if r.PageToken != "" {
		presented, err := decodePage(r.PageToken)
		if err != nil {
			return ViewerGrants{}, err
		}
		from = presented.From
		presented.From = 0
		if presented != binding || from > len(all) {
			return ViewerGrants{}, ErrStale
		}
	}
	end := min(from+size, len(all))
	out.Resources = all[from:end]
	if end < len(all) {
		binding.From = end
		out.NextPage = encodePage(binding)
	}
	return out, nil
}

// pageToken is what a ListViewerGrants page token binds. It is not a
// credential: every page verifies the capability again, and a token only
// positions a read of the caller's own grants.
type pageToken struct {
	Digest   string `json:"d"`
	Revision uint64 `json:"r"`
	Expiry   int64  `json:"e,omitempty"`
	From     int    `json:"f,omitempty"`
}

func encodePage(t pageToken) string {
	raw, _ := json.Marshal(t)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodePage(encoded string) (pageToken, error) {
	var t pageToken
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > 1024 || json.Unmarshal(raw, &t) != nil || t.From < 0 {
		return pageToken{}, domain.Malformed("the page token is not one this host issued")
	}
	return t, nil
}

// viewerDigest binds a page to who asked what: the organization, the module
// asking, the viewer and the subjects counted for them now, the kinds and the
// action. A viewer who left a team is another digest.
func viewerDigest(caller authority.AccessCaller, kinds []string, action string) string {
	subjects := make([]string, len(caller.Owner.Subjects))
	for i, s := range caller.Owner.Subjects {
		subjects[i] = string(s.Kind) + ":" + s.ID
	}
	slices.Sort(subjects)
	raw, _ := json.Marshal([]any{caller.Organization, caller.Server.Principal, caller.Owner.Principal, subjects, kinds, action})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func party(p authority.AccessParty) Party {
	return Party{Subjects: p.Subjects, Owns: p.Owns, Scopes: p.Scopes}
}

func key(org string, t Target, subject domain.AccessSubject) domain.AccessKey {
	return domain.AccessKey{Organization: org, Kind: t.Kind, ResourceID: t.ResourceID, Version: t.Version, Subject: subject}
}

// kindsOf are the kinds a placement names, the resource's first.
func kindsOf(p Placement) []string {
	kinds := []string{p.Resource.Kind}
	for _, a := range p.Ancestors {
		if !slices.Contains(kinds, a.Kind) {
			kinds = append(kinds, a.Kind)
		}
	}
	return kinds
}

// validPlacement holds a placement to what the contract admits: a kind and a
// usable id on every node (decide.ValidResourceID), at most MaxAncestors
// ancestors, none twice and none the resource itself.
func validPlacement(p Placement) error {
	if len(p.Ancestors) > MaxAncestors {
		return domain.Malformed("a placement names at most %d ancestors, not %d", MaxAncestors, len(p.Ancestors))
	}
	seen := map[Ref]bool{}
	for _, n := range append([]Node{p.Resource}, p.Ancestors...) {
		if n.Kind == "" {
			return domain.Malformed("a placed resource names its kind")
		}
		if err := decide.ValidResourceID(n.ResourceID); err != nil {
			return err
		}
		if err := validVersion(n.Version); err != nil {
			return err
		}
		ref := Ref{Kind: n.Kind, ResourceID: n.ResourceID}
		if seen[ref] {
			return domain.Malformed("a placement names each resource once")
		}
		seen[ref] = true
	}
	return nil
}

// validVersion admits an empty version or one usable as an id is.
func validVersion(version string) error {
	if version == "" {
		return nil
	}
	if err := decide.ValidResourceID(version); err != nil {
		return domain.Malformed("version %q is not a usable version", version)
	}
	return nil
}

func validSubject(s domain.AccessSubject) error {
	switch s.Kind {
	case domain.AccessPerson, domain.AccessTeam, domain.AccessInstallation:
		if s.ID != "" {
			return nil
		}
	}
	return domain.Malformed("a grant names exactly one of a person, a team and an installation")
}

// validActions are the actions of a grant, sorted and distinct: at least one,
// at most MaxActions, each one of Grantable.
func validActions(actions []string) ([]string, error) {
	out := slices.Clone(actions)
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) == 0 || len(out) > MaxActions {
		return nil, domain.Malformed("a grant gives between 1 and %d actions, not %d", MaxActions, len(out))
	}
	for _, a := range out {
		if !slices.Contains(Grantable, a) {
			return nil, domain.Malformed("%s is not an action a grant gives: a grant gives %s", fmt.Sprintf("%q", a), strings.Join(Grantable, ", "))
		}
	}
	return out, nil
}
