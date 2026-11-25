// Package obintoken admits a user token issued by the OBIN platform's
// token-exchange to a host of this authority.
//
// It decides nothing about what the user may do: it answers who the token
// names here (organisation, person, installation, role, and the services it
// passed through), and the host opens that person a session limited to that
// role, so every grant is still derived by the shared core from the host's
// own state.
//
// A host has no Adapter unless it is configured one: off is the absence of
// the value. An Adapter refuses whatever it cannot map, by name:
//
//   - the token: an algorithm other than RS256, a key the configuration does
//     not hold, another issuer or audience, a lifetime longer than the
//     platform gives a user token, a member given twice, a principal that is
//     not a user, and any claim the platform gives a meaning this host has no
//     counterpart for (an acting agent, a synthetic user, ...);
//   - the tenant, the user, the solution and the role, each through Mapping;
//   - the role's evidence: authorization_assignment_digest is recomputed from
//     the claims it covers, at the one version this package knows;
//   - the role version: the token carries none, so it is read where the
//     platform's front door reads it (SignIns, token-exchange's sign-in
//     check). A token minted at or before the member's revocation epoch is
//     refused; once the member's roles version is seen to move, every token
//     minted before that moment is refused, and stays refused if the version
//     moves back;
//   - the actor chain: every service in act must be one Mapping names.
package obintoken

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"
)

// AssignmentVersion is the one version of the authorization assignment
// evidence this package recomputes (token-exchange's
// AUTHORIZATION_ASSIGNMENT_VERSION).
const AssignmentVersion = "authorization-assignment-v1"

// MaxLifetime is the longest a user token lives on the platform
// (USER_TOKEN_TTL_CEILING_SECONDS). A longer one is not a user token.
const MaxLifetime = 15 * time.Minute

// MaxActors is how deep an actor chain is read when Config names no limit.
const MaxActors = 4

// clockSkew is how far in this host's future a token may say it was minted.
const clockSkew = 30 * time.Second

// minKeyBits is the smallest RSA modulus a signature is judged by.
const minKeyBits = 2048

// ErrRefused is every refusal of this package.
var ErrRefused = errors.New("obintoken: refused")

// Refusal is one refusal: what could not be verified or mapped.
type Refusal struct {
	// Reason names what was refused, without the token.
	Reason string
	// TokenID is the token's jti when a verified token is refused for good
	// (its user's sign-ins revoked, their membership ended, their role
	// version moved), so a host ends what it opened for that token. It is
	// empty for a token that was not verified and for a standing that could
	// not be read, which refuses this call and ends nothing.
	TokenID string
}

func (r *Refusal) Error() string { return "obintoken: " + r.Reason }

// Is makes every Refusal answer errors.Is(err, ErrRefused).
func (r *Refusal) Is(target error) bool { return target == ErrRefused }

func refuse(format string, args ...any) error {
	return &Refusal{Reason: fmt.Sprintf(format, args...)}
}

// Mapping is what the platform's names are on this host. A name it does not
// hold is refused: nothing is defaulted and nothing is passed through.
type Mapping struct {
	// Tenants: tenant_id to organisation.
	Tenants map[string]string
	// Users: organisation, then the token's sub, to person.
	Users map[string]map[string]string
	// Solutions: organisation, then authorization_solution_id, to installation.
	Solutions map[string]map[string]string
	// Roles: authorization_solution_id, then solution_role, to the role of
	// that installation.
	Roles map[string]map[string]string
	// Actors: the sub of a service in the token's act chain, to its name here.
	Actors map[string]string
}

// Standing is a member's standing as token-exchange's sign-in check answers
// it (SignInCheckResponse).
type Standing struct {
	// Epoch is the member's revocation epoch, in Unix seconds; zero for none.
	Epoch int64
	// Roles is the member's roles version; empty for no member.
	Roles string
}

// SignIns reads a member's standing from the platform. An error is a refusal:
// an unknown standing admits nobody.
type SignIns interface {
	Check(ctx context.Context, tenant, user string) (Standing, error)
}

// Config is an Adapter's configuration. Every field but Now and MaxActors is
// required.
type Config struct {
	// Issuer and Audience are the token's iss and aud, exactly.
	Issuer, Audience string
	// Keys are the issuer's public keys by key id (ParseKeySet).
	Keys    map[string]*rsa.PublicKey
	Mapping Mapping
	SignIns SignIns
	// Now is the host's clock; time.Now when nil.
	Now func() time.Time
	// MaxActors bounds the actor chain; MaxActors when zero.
	MaxActors int
}

// Admission is who a verified token names on this host.
type Admission struct {
	// TokenID is the token's jti.
	TokenID string
	// Tenant, User and Solution are the platform's names, as the token gave them.
	Tenant, User, Solution string
	// Organization, Person, Installation and Role are this host's.
	Organization, Person, Installation, Role string
	// Actors is the services the token passed through as this host names
	// them, the current actor first.
	Actors []string
	// RolesVersion is the member's roles version the token was admitted under.
	RolesVersion string
	// Scopes is the token's scope claim, as the platform decided it. This
	// host derives nothing from it.
	Scopes              []string
	IssuedAt, ExpiresAt time.Time
}

// Adapter admits tokens; safe for concurrent use.
type Adapter struct {
	cfg Config

	mu sync.Mutex
	// standing is the roles version last seen for each member and when this
	// host saw it begin, in Unix seconds (zero: the first one seen).
	standing map[string]seen
	// refused is the tokens refused for their role version, kept until they
	// expire, so a version that moves back revives none.
	refused map[string]time.Time
}

type seen struct {
	roles string
	since int64
}

// New builds an Adapter, refusing a configuration that could admit a token it
// cannot fully judge.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Issuer == "" || cfg.Audience == "":
		return nil, errors.New("obintoken: the issuer and the audience are required")
	case len(cfg.Keys) == 0:
		return nil, errors.New("obintoken: no issuer key is configured")
	case cfg.SignIns == nil:
		return nil, errors.New("obintoken: no sign-in check is configured, so no role version could be read")
	}
	for id, key := range cfg.Keys {
		if id == "" || key == nil || key.N == nil || key.N.BitLen() < minKeyBits {
			return nil, fmt.Errorf("obintoken: key %q is not an RSA public key of at least %d bits with a key id", id, minKeyBits)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxActors == 0 {
		cfg.MaxActors = MaxActors
	}
	return &Adapter{cfg: cfg, standing: map[string]seen{}, refused: map[string]time.Time{}}, nil
}

// ParseKeySet reads a JSON Web Key Set holding RS256 public keys, as the
// issuer publishes it. Private or symmetric key material, a key with no key
// id, a key id given twice and any key that is not an RSA signature key are
// refused: the set is trusted whole or not at all.
func ParseKeySet(document []byte) (map[string]*rsa.PublicKey, error) {
	if err := noDuplicateMembers(document); err != nil {
		return nil, fmt.Errorf("obintoken: key set: %w", err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(document, &set); err != nil {
		return nil, fmt.Errorf("obintoken: key set: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("obintoken: key set: no key")
	}
	out := map[string]*rsa.PublicKey{}
	for n, jwk := range set.Keys {
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, has := jwk[private]; has {
				return nil, fmt.Errorf("obintoken: key set: key %d carries private or symmetric material", n)
			}
		}
		text := func(name string) string { s, _ := jwk[name].(string); return s }
		id := text("kid")
		if id == "" {
			return nil, fmt.Errorf("obintoken: key set: key %d has no key id", n)
		}
		if _, twice := out[id]; twice {
			return nil, fmt.Errorf("obintoken: key set: key id %q names two keys", id)
		}
		if text("kty") != "RSA" || (text("alg") != "" && text("alg") != "RS256") || (text("use") != "" && text("use") != "sig") {
			return nil, fmt.Errorf("obintoken: key set: key %q is not an RS256 signature key", id)
		}
		modulus, err := base64.RawURLEncoding.DecodeString(text("n"))
		if err != nil || len(modulus) == 0 {
			return nil, fmt.Errorf("obintoken: key set: key %q has no modulus", id)
		}
		exponent, err := base64.RawURLEncoding.DecodeString(text("e"))
		if err != nil || len(exponent) == 0 || len(exponent) > 4 {
			return nil, fmt.Errorf("obintoken: key set: key %q has no usable exponent", id)
		}
		e := int(new(big.Int).SetBytes(exponent).Int64())
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}
		if key.N.BitLen() < minKeyBits || e < 3 || e%2 == 0 {
			return nil, fmt.Errorf("obintoken: key set: key %q is weaker than %d bits or has an unusable exponent", id, minKeyBits)
		}
		out[id] = key
	}
	return out, nil
}

// unmapped is the claims the platform gives a meaning that this host has no
// counterpart for. A token carrying one is refused rather than admitted as
// the plain user token it would otherwise read as.
var unmapped = []string{
	"acting_agent", "agent_allowance", "agent", "agent_id", "agent_version", "caused_by", "ceiling_snapshot_hash",
	"synthetic", "impersonator", "home_tenant_id", "identity_role_attested_from", "token_use", "org_id", "org_role", "role", "azp", "nbf",
}

// Admit verifies token and answers who it names on this host, or a Refusal.
func (a *Adapter) Admit(ctx context.Context, token string) (Admission, error) {
	claims, err := a.verify(token)
	if err != nil {
		return Admission{}, err
	}
	adm, err := a.read(claims)
	if err != nil {
		return Admission{}, err
	}
	if err := a.standingOf(ctx, &adm); err != nil {
		return Admission{}, err
	}
	return adm, nil
}

// verify checks the token's framing and signature and answers its claims.
func (a *Adapter) verify(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, refuse("the token is not a signed JWT")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, refuse("the token's header does not decode")
	}
	header, err := object(headerBytes)
	if err != nil {
		return nil, refuse("the token's header: %v", err)
	}
	if alg, _ := header["alg"].(string); alg != "RS256" {
		return nil, refuse("the token is not signed with RS256")
	}
	if typ, has := header["typ"]; has && typ != "JWT" {
		return nil, refuse("the token's type is not JWT")
	}
	if _, has := header["crit"]; has {
		return nil, refuse("the token's header requires an extension this host does not know")
	}
	kid, _ := header["kid"].(string)
	key, known := a.cfg.Keys[kid]
	if kid == "" || !known {
		return nil, refuse("the token names no key of the configured issuer")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, refuse("the token's signature does not decode")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, refuse("the token's signature does not verify")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, refuse("the token's claims do not decode")
	}
	claims, err := object(payload)
	if err != nil {
		return nil, refuse("the token's claims: %v", err)
	}
	return claims, nil
}

// read checks the verified claims and maps every name.
func (a *Adapter) read(claims map[string]any) (Admission, error) {
	text := func(name string) (string, error) {
		value, ok := claims[name].(string)
		if !ok || value == "" {
			return "", refuse("the token's %s is missing or not a string", name)
		}
		return value, nil
	}
	seconds := func(name string) (int64, error) {
		number, ok := claims[name].(json.Number)
		if !ok {
			return 0, refuse("the token's %s is missing or not a number", name)
		}
		value, err := number.Int64()
		if err != nil || value <= 0 {
			return 0, refuse("the token's %s is not a time in whole seconds", name)
		}
		return value, nil
	}
	if iss, err := text("iss"); err != nil {
		return Admission{}, err
	} else if iss != a.cfg.Issuer {
		return Admission{}, refuse("the token is another issuer's")
	}
	// One audience, as a string: the platform mints a token for one resource.
	if aud, err := text("aud"); err != nil {
		return Admission{}, err
	} else if aud != a.cfg.Audience {
		return Admission{}, refuse("the token is for another audience")
	}
	issued, err := seconds("iat")
	if err != nil {
		return Admission{}, err
	}
	expires, err := seconds("exp")
	if err != nil {
		return Admission{}, err
	}
	now := a.cfg.Now()
	switch {
	case !now.Before(time.Unix(expires, 0)):
		return Admission{}, refuse("the token expired")
	case time.Unix(issued, 0).After(now.Add(clockSkew)):
		return Admission{}, refuse("the token says it was minted in the future")
	case expires <= issued || time.Duration(expires-issued)*time.Second > MaxLifetime:
		return Admission{}, refuse("the token lives longer than a user token does")
	}
	adm := Admission{IssuedAt: time.Unix(issued, 0), ExpiresAt: time.Unix(expires, 0)}
	if adm.TokenID, err = text("jti"); err != nil {
		return Admission{}, err
	}
	if kind, err := text("principal_kind"); err != nil {
		return Admission{}, err
	} else if kind != "user" {
		return Admission{}, refuse("the token's principal is %q, and only a user's is admitted", kind)
	}
	for _, name := range unmapped {
		if _, has := claims[name]; has {
			return Admission{}, refuse("the token carries %s, which this host cannot map", name)
		}
	}
	if adm.Tenant, err = text("tenant_id"); err != nil {
		return Admission{}, err
	}
	if adm.User, err = text("sub"); err != nil {
		return Admission{}, err
	}
	if adm.Solution, err = text("authorization_solution_id"); err != nil {
		return Admission{}, err
	}
	role, err := text("solution_role")
	if err != nil {
		return Admission{}, err
	}
	evidence, err := text("authorization_assignment_digest")
	if err != nil {
		return Admission{}, err
	}
	if evidence != AssignmentDigest(adm.User, adm.Tenant, adm.Solution, role) {
		return Admission{}, refuse("the token's role is not the one its assignment evidence covers, at %s", AssignmentVersion)
	}
	scopes, ok := claims["scope"].([]any)
	if !ok {
		return Admission{}, refuse("the token's scope is missing or not a list")
	}
	for _, scope := range scopes {
		s, ok := scope.(string)
		if !ok || s == "" {
			return Admission{}, refuse("the token's scope holds a value that is not a string")
		}
		adm.Scopes = append(adm.Scopes, s)
	}

	var mapped bool
	if adm.Organization, mapped = a.cfg.Mapping.Tenants[adm.Tenant]; !mapped || adm.Organization == "" {
		return Admission{}, refuse("the token's tenant is no organisation of this host")
	}
	if adm.Person, mapped = a.cfg.Mapping.Users[adm.Organization][adm.User]; !mapped || adm.Person == "" {
		return Admission{}, refuse("the token's user is no person of %s", adm.Organization)
	}
	if adm.Installation, mapped = a.cfg.Mapping.Solutions[adm.Organization][adm.Solution]; !mapped || adm.Installation == "" {
		return Admission{}, refuse("the token's solution is no installation of %s", adm.Organization)
	}
	if adm.Role, mapped = a.cfg.Mapping.Roles[adm.Solution][role]; !mapped || adm.Role == "" {
		return Admission{}, refuse("the token's role is no role of that installation")
	}
	if adm.Actors, err = a.actors(claims["act"]); err != nil {
		return Admission{}, err
	}
	return adm, nil
}

// actors maps the act chain, the current actor first. A token with no actor,
// a link that is not an object naming its service, a service this host does
// not name, or a chain deeper than the limit is refused.
func (a *Adapter) actors(act any) ([]string, error) {
	var out []string
	for link := act; ; {
		actor, ok := link.(map[string]any)
		if !ok {
			return nil, refuse("the token's actor chain is missing or malformed")
		}
		if len(out) == a.cfg.MaxActors {
			return nil, refuse("the token's actor chain is deeper than %d", a.cfg.MaxActors)
		}
		sub, _ := actor["sub"].(string)
		name, mapped := a.cfg.Mapping.Actors[sub]
		if sub == "" || !mapped || name == "" {
			return nil, refuse("the token's actor chain names a service this host does not know")
		}
		out = append(out, name)
		next, more := actor["act"]
		if !more {
			return out, nil
		}
		link = next
	}
}

// standingOf reads the member's standing and refuses a token minted before
// it: at or before the revocation epoch, or before the roles version this
// host last saw begin.
func (a *Adapter) standingOf(ctx context.Context, adm *Admission) error {
	standing, err := a.cfg.SignIns.Check(ctx, adm.Tenant, adm.User)
	if err != nil {
		return refuse("the user's role version could not be read")
	}
	// From here the token is the issuer's and the refusal is of the token
	// itself: it names it.
	final := func(reason string) error { return &Refusal{Reason: reason, TokenID: adm.TokenID} }
	if standing.Roles == "" {
		return final("the user is no member of the tenant")
	}
	issued := adm.IssuedAt.Unix()
	if standing.Epoch > 0 && issued <= standing.Epoch {
		return final("the token was minted before the user's sign-ins were revoked")
	}
	now := a.cfg.Now()
	member := adm.Tenant + "\x00" + adm.User
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, until := range a.refused {
		if !now.Before(until) {
			delete(a.refused, id)
		}
	}
	last, known := a.standing[member]
	switch {
	case !known:
		last = seen{roles: standing.Roles}
	case last.roles != standing.Roles:
		last = seen{roles: standing.Roles, since: now.Unix()}
	}
	a.standing[member] = last
	_, already := a.refused[adm.TokenID]
	// A token minted in the second the version was seen to move is refused
	// too: it cannot be told from one minted just before.
	if already || issued <= last.since {
		a.refused[adm.TokenID] = adm.ExpiresAt
		return final("the user's role version moved since the token was minted")
	}
	adm.RolesVersion = standing.Roles
	return nil
}

// AssignmentDigest is token-exchange's authorization_assignment_digest for
// one assignment: the bare lowercase SHA-256 of its canonical JSON
// (signing.canonical_authorization_assignment_bytes), members sorted, no
// spaces, Unicode literal.
func AssignmentDigest(subject, tenant, solution, role string) string {
	var b strings.Builder
	for n, member := range [][2]string{
		{"assignment_tenant_id", tenant}, {"authorization_solution_id", solution}, {"solution_role", role},
		{"subject_id", subject}, {"version", AssignmentVersion},
	} {
		b.WriteString(map[bool]string{true: "{", false: ","}[n == 0])
		quote(&b, member[0])
		b.WriteByte(':')
		quote(&b, member[1])
	}
	b.WriteByte('}')
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// quote writes s as Python's json.dumps(ensure_ascii=False) does: the two
// structural characters and the control characters escaped, the rest literal.
func quote(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// object decodes one JSON object, numbers kept as written, refusing a member
// given twice at any depth and anything after the object.
func object(document []byte) (map[string]any, error) {
	if err := noDuplicateMembers(document); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil || out == nil {
		return nil, errors.New("not a JSON object")
	}
	return out, nil
}

// noDuplicateMembers refuses a document in which an object names a member
// twice (a parser that keeps the first and one that keeps the last would read
// two different tokens), and a document with anything after its value.
func noDuplicateMembers(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := walk(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("more than one JSON value")
	}
	return nil
}

func walk(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("not JSON")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		members := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return errors.New("not JSON")
			}
			name, _ := key.(string)
			if members[name] {
				return fmt.Errorf("member %q is given twice", name)
			}
			members[name] = true
			if err := walk(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walk(decoder); err != nil {
				return err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("not JSON")
	}
	return nil
}
