package state_test

import (
	"testing"

	"gateway/pkg/business/approvalstest"
	"gateway/pkg/business/state"
)

func TestMemoryApprovalsContract(t *testing.T) {
	var memory state.MemoryApprovals
	approvalstest.Contract(t, func(*testing.T) state.Approvals { return &memory })
}
