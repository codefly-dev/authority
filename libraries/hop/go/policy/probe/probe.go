// Package probe makes the call: for every procedure a module's published
// contract declares, it holds exactly the declared policy and invokes the
// handler that serves it. Every other check of a method policy compares one
// statement of it with another; this one compares the statement with what the
// module does. It takes no exception: a procedure with no case, no handler, or
// a handler that decides a rule its declaration does not state, fails by name.
package probe

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Call makes one real call to method through the module's test hop (deciding
// with policy.Admit on the same contract) and into its handler, as a caller
// holding exactly holding on a resource the module's fixture owns, and of the
// principal kind the method is for. It returns the handler's answer. The
// module supplies the request that makes the call succeed; a method it has no
// request for returns an error saying so.
type Call func(method string, holding []policy.Permission) error

// Run fails t for each finding of Check.
func Run(t *testing.T, contract []byte, call Call) {
	t.Helper()
	findings, err := Check(contract, call)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Error(finding)
	}
}

// Check holds each procedure of the contract (contract.binpb, the artifact a
// deployed hop's policy is read from) against its handler:
//
//   - holding exactly what the procedure declares, the call succeeds. Any
//     other answer is a finding: a refusal means the handler requires
//     something undeclared; NotFound means the refusal is concealed or the
//     fixture is missing; Unimplemented means a policy is declared for a
//     handler that does not exist.
//   - holding all but one required permission, the call is PermissionDenied,
//     so the hop in the test is deciding this declaration and names it.
func Check(contract []byte, call Call) ([]string, error) {
	declared, err := policy.Contract(contract)
	if err != nil {
		return nil, err
	}
	if len(declared) == 0 {
		return nil, fmt.Errorf("the contract declares no procedure, so the probe would compare nothing")
	}
	var findings []string
	for _, method := range slices.Sorted(maps.Keys(declared)) {
		m := declared[method]
		if !m.Declares() || m.Validate() != nil {
			findings = append(findings, fmt.Sprintf("%s declares no readable policy; the hop refuses every call to it", method))
			continue
		}
		if err := call(method, m.Requires); err != nil {
			findings = append(findings, fmt.Sprintf("%s: holding exactly what it declares (%q), the call is answered %v (%v); the declaration and the handler disagree",
				method, m.Requires, status.Code(err), err))
		}
		for i, without := range m.Requires {
			less := slices.Concat(m.Requires[:i:i], m.Requires[i+1:])
			if err := call(method, less); status.Code(err) != codes.PermissionDenied {
				findings = append(findings, fmt.Sprintf("%s: without %s the call is answered %v, want PermissionDenied naming it", method, without, status.Code(err)))
			}
		}
	}
	return findings, nil
}
