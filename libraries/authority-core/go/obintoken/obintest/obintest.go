// Package obintest is a test issuer of OBIN platform user tokens: a member
// directory, the roles each solution gives, and a signing key, minting the
// claims token-exchange's build_claims mints and answering its sign-in check.
// It holds a private key generated per test and never leaves a test binary.
package obintest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/obintoken"
)

// KeyID is the key id the issuer signs under.
const KeyID = "obintest-1"

// Lifetime is how long a minted token lives (TOKEN_TTL_SECONDS' default).
const Lifetime = 10 * time.Minute

// Member is one member record of one tenant.
type Member struct {
	// Status is "active" for a member who may be minted a token.
	Status string
	// TenantRole is the role held in the tenant (identity_role).
	TenantRole string
	// Solutions is the role held in each solution.
	Solutions map[string]string
}

// Issuer is the test issuer. Its zero value is not usable: New.
type Issuer struct {
	// Name is the tokens' iss.
	Name string
	// Now is the issuer's clock.
	Now func() time.Time

	key *rsa.PrivateKey

	mu sync.Mutex
	// members: tenant, then user.
	members map[string]map[string]*Member
	// scopes: solution, then role, to the scopes that role is minted.
	scopes map[string]map[string][]string
	epochs map[string]int64
	down   bool
	serial int
}

// New is an issuer named name on clock now, with a key of its own.
func New(t testing.TB, name string, now func() time.Time) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &Issuer{Name: name, Now: now, key: key, members: map[string]map[string]*Member{}, scopes: map[string]map[string][]string{}, epochs: map[string]int64{}}
}

// KeySet is the issuer's public keys as it publishes them, a JSON Web Key Set.
func (i *Issuer) KeySet() []byte {
	out, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": KeyID, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(i.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(i.key.E)).Bytes()),
	}}})
	return out
}

// Grants declares the scopes role of solution is minted.
func (i *Issuer) Grants(solution, role string, scopes ...string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.scopes[solution] == nil {
		i.scopes[solution] = map[string][]string{}
	}
	i.scopes[solution][role] = scopes
}

// SetMember writes user's record in tenant, replacing any before it.
func (i *Issuer) SetMember(tenant, user string, m Member) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.members[tenant] == nil {
		i.members[tenant] = map[string]*Member{}
	}
	m.Solutions = cloneRoles(m.Solutions)
	i.members[tenant][user] = &m
}

// SetRole gives user role in solution, or takes their role away when role is
// empty: the member's roles version moves.
func (i *Issuer) SetRole(tenant, user, solution, role string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	m := i.members[tenant][user]
	if m == nil {
		panic("obintest: no such member")
	}
	if role == "" {
		delete(m.Solutions, solution)
		return
	}
	if m.Solutions == nil {
		m.Solutions = map[string]string{}
	}
	m.Solutions[solution] = role
}

// Revoke sets user's revocation epoch to now: tokens minted before it are no
// longer good.
func (i *Issuer) Revoke(tenant, user string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.epochs[tenant+"\x00"+user] = i.Now().Unix()
}

// Down makes the sign-in check fail, as when the directory cannot be read.
func (i *Issuer) Down(down bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.down = down
}

// Check is token-exchange's sign-in check: the member's revocation epoch and
// roles version, an empty version for no member, an error when it cannot say.
func (i *Issuer) Check(_ context.Context, tenant, user string) (obintoken.Standing, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.down {
		return obintoken.Standing{}, errors.New("service temporarily unavailable")
	}
	m := i.members[tenant][user]
	if m == nil {
		return obintoken.Standing{Epoch: i.epochs[tenant+"\x00"+user]}, nil
	}
	return obintoken.Standing{Epoch: i.epochs[tenant+"\x00"+user], Roles: rolesVersion(m)}, nil
}

// rolesVersion is directory.roles_version: a short hash of the member's
// status, tenant role and role in each solution.
func rolesVersion(m *Member) string {
	// encoding/json sorts map keys, as json.dumps(sort_keys=True) does.
	document, _ := json.Marshal(map[string]any{"status": m.Status, "tenant": m.TenantRole, "solutions": m.Solutions})
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:])[:16]
}

// Actor is one service of a token's actor chain.
type Actor struct{ Sub, Service string }

// Mint is the user token token-exchange mints user of tenant for audience and
// solution, asked by the services in actors, the current one first. It
// refuses, as token-exchange does, a user with no active member record in the
// tenant; a member with no role in the solution is minted a token with no
// solution role and no scope.
func (i *Issuer) Mint(tenant, user, audience, solution string, actors ...Actor) (string, error) {
	claims, err := i.Claims(tenant, user, audience, solution, actors...)
	if err != nil {
		return "", err
	}
	return i.Sign(claims), nil
}

// Claims is the claims Mint signs, for a test that changes one before Sign.
func (i *Issuer) Claims(tenant, user, audience, solution string, actors ...Actor) (map[string]any, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	m := i.members[tenant][user]
	if m == nil || m.Status != "active" {
		return nil, fmt.Errorf("obintest: %s is no active member of %s", user, tenant)
	}
	if len(actors) == 0 {
		return nil, errors.New("obintest: a token is minted for a calling service")
	}
	var act map[string]any
	for _, actor := range slices.Backward(actors) {
		link := map[string]any{"sub": actor.Sub, "service": actor.Service}
		if act != nil {
			link["act"] = act
		}
		act = link
	}
	now := i.Now().Unix()
	i.serial++
	role := m.Solutions[solution]
	scopes := append([]string{}, i.scopes[solution][role]...)
	claims := map[string]any{
		"iss": i.Name, "sub": user, "aud": audience, "tenant_id": tenant, "act": act, "scope": scopes,
		"iat": now, "exp": now + int64(Lifetime/time.Second), "jti": fmt.Sprintf("obintest-%d-%d", now, i.serial),
		"identity_role": nilIfEmpty(m.TenantRole), "solution_role": nilIfEmpty(role), "principal_kind": "user",
		"authorization_solution_id": solution,
	}
	if role != "" {
		claims["authorization_assignment_digest"] = obintoken.AssignmentDigest(user, tenant, solution, role)
	}
	return claims, nil
}

// Sign signs claims with the issuer's key, RS256.
func (i *Issuer) Sign(claims map[string]any) string {
	return i.SignWith(map[string]any{"alg": "RS256", "typ": "JWT", "kid": KeyID}, claims, i.key)
}

// SignWith signs claims under header with key: for a test's forged tokens.
func (i *Issuer) SignWith(header, claims map[string]any, key *rsa.PrivateKey) string {
	head, _ := json.Marshal(header)
	body, _ := json.Marshal(claims)
	return SignRaw(head, body, key)
}

// SignRaw signs a header and a payload given as bytes, so a test can sign a
// document encoding/json would not write (a member given twice).
func SignRaw(header, payload []byte, key *rsa.PrivateKey) string {
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// Key is the issuer's private key, for SignWith and SignRaw.
func (i *Issuer) Key() *rsa.PrivateKey { return i.key }

// Allows is the platform's own decision: whether a token minted now for user
// of tenant at solution carries scope. No token, no.
func (i *Issuer) Allows(tenant, user, solution, scope string) bool {
	claims, err := i.Claims(tenant, user, "decision", solution, Actor{Sub: "decision", Service: "decision"})
	if err != nil {
		return false
	}
	return slices.Contains(claims["scope"].([]string), scope)
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func cloneRoles(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
