package solutionhost_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
	"github.com/stretchr/testify/require"
)

// Every record is handed to core's resolution as supplied, in both
// spellings and both classifications, and nothing of another group.
func TestConfigurationValuesKeepEveryRecord(t *testing.T) {
	infos := []*basev1.ConfigurationInformation{
		{Name: "ledger", ConfigurationValues: []*basev1.ConfigurationValue{{Key: "store-audience", Value: "store"}}},
		{Name: "ledger", ConfigurationValues: []*basev1.ConfigurationValue{{Key: "store-audience", Value: "store", Secret: true}}},
		{Name: "other", ConfigurationValues: []*basev1.ConfigurationValue{{Key: "store-audience", Value: "elsewhere"}}},
	}
	records, err := solutionhost.ConfigurationValues(infos).Records("ledger")
	require.NoError(t, err)
	require.Equal(t, []modulecontract.Record{{Key: "store-audience", Value: "store"}, {Key: "store-audience", Value: "store", Secret: true}}, records)
}

// Core's resolution kit drives ConfigurationValues over one group's records,
// held the way a workspace configuration read holds them: a provider that
// selected among them would fail it.
func TestTheResolutionKitRunsThroughConfigurationValues(t *testing.T) {
	modulecontract.RunResolution(t, func(group string, records []modulecontract.Record) modulecontract.Values {
		values := make([]*basev1.ConfigurationValue, 0, len(records))
		for _, record := range records {
			values = append(values, &basev1.ConfigurationValue{Key: record.Key, Value: record.Value, Secret: record.Secret})
		}
		return solutionhost.ConfigurationValues([]*basev1.ConfigurationInformation{{Name: group, ConfigurationValues: values}})
	})
}

// A unit still shipping the retired roles declaration is refused naming it;
// one that does not, or no directory at all, ships nothing to refuse.
func TestRefuseRetiredRoles(t *testing.T) {
	require.NoError(t, solutionhost.RefuseRetiredRoles(""))
	dir := t.TempDir()
	require.NoError(t, solutionhost.RefuseRetiredRoles(dir))
	require.NoError(t, os.WriteFile(filepath.Join(dir, solutionhost.RetiredRolesFileName), []byte("roles: []\n"), 0o600))
	require.ErrorContains(t, solutionhost.RefuseRetiredRoles(dir), "roles.codefly.yaml is no longer read")
}
