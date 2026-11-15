package authority_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// withRoles is solution "rolled" at generation, declaring roles, read from source.
func withRoles(generation uint64, source string, roles map[string][]*basev0.WorkScopeV1) domain.Module {
	m := solution("rolled", true)
	m.Generation, m.Source, m.Roles = generation, source, roles
	return m
}

// Which roles a delivery may declare is held on what is NEW to the core, by
// the library itself, so no host can diverge: Admit and ApplyModule refuse a
// new generation declaring a third role or missing user (decide.PageRoles).
// A generation the core already holds is never refused for it: a host that
// holds one declaring old roles — composed when only core's render refused
// them — reads it again at boot (RereadModule) and replays it, and its next
// delivery of admin and user moves the old roles' holders (the crossover).
func TestOnlyANewGenerationIsHeldToThePageRoles(t *testing.T) {
	h := newHarness(t)
	cfg := h.cfg
	cfg.AnyRoleNames = false
	host, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	own, consumed := sc("rolled.note", "read", "write"), sc(kind, "read")
	legacy := withRoles(1, "held-1", map[string][]*basev0.WorkScopeV1{
		domain.LegacyInstallerRole: {own}, "editor": {own, consumed}, "viewer": {sc("rolled.note", "read")},
	})
	// Held by the core as an older host composed it.
	if _, err := h.svc.ApplyModule(h.ctx, legacy); err != nil {
		t.Fatalf("an older host composes the legacy generation: %v", err)
	}

	if reread, err := host.RereadModule(h.ctx, legacy); err != nil || reread {
		t.Fatalf("the held legacy generation read again at boot: reread %t, %v", reread, err)
	}
	if _, err := host.ApplyModule(h.ctx, legacy); err != nil {
		t.Fatalf("the held legacy generation delivered again is a replay: %v", err)
	}
	if err := host.Admit(h.ctx, legacy); err != nil {
		t.Fatalf("admitting the held legacy generation again: %v", err)
	}

	for name, c := range map[string]struct {
		roles   map[string][]*basev0.WorkScopeV1
		refusal string
	}{
		"a third role": {map[string][]*basev0.WorkScopeV1{domain.AdminRole: {own}, domain.UserRole: {own}, "viewer": {own}},
			`declares role "viewer", which is neither "admin" nor "user"`},
		"no user": {map[string][]*basev0.WorkScopeV1{domain.AdminRole: {own}}, `none is "user"`},
		"an old role beside admin and user": {map[string][]*basev0.WorkScopeV1{domain.AdminRole: {own}, domain.UserRole: {own}, "editor": {own}},
			`declares role "editor"`},
	} {
		next := withRoles(2, "new-2", c.roles)
		if err := host.Admit(h.ctx, next); err == nil || !strings.Contains(err.Error(), c.refusal) {
			t.Fatalf("%s: Admit answered %v, want a refusal naming %q", name, err, c.refusal)
		}
		if _, err := host.ApplyModule(h.ctx, next); err == nil || !strings.Contains(err.Error(), c.refusal) {
			t.Fatalf("%s: ApplyModule answered %v, want a refusal naming %q", name, err, c.refusal)
		}
	}
	if _, err := host.ApplyModule(h.ctx, withRoles(2, "new-2", map[string][]*basev0.WorkScopeV1{domain.AdminRole: {own, consumed}, domain.UserRole: {own}})); err != nil {
		t.Fatalf("the next delivery declaring admin and user: %v", err)
	}
}
