package workloadidentity_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go/workloadidentity"
)

// A cell spells a workload by rule: namespace = module, account = service.
// The rule reads both ways and never needs a declaration.
func TestACellSpellsAWorkloadByRule(t *testing.T) {
	workload := workloadidentity.Workload{TrustDomain: "cluster.local", Module: "documents", Service: "backend"}
	if workload.KubernetesNamespace() != "documents" || workload.KubernetesAccount() != "backend" {
		t.Fatalf("pair = %s/%s", workload.KubernetesNamespace(), workload.KubernetesAccount())
	}
	if workload.SPIFFEID() != "spiffe://cluster.local/ns/documents/sa/backend" {
		t.Fatalf("spiffe id = %s", workload.SPIFFEID())
	}
	back := workloadidentity.FromKubernetes("cluster.local", "documents", "backend")
	if back != workload {
		t.Fatalf("read back = %+v", back)
	}
	carrier := workloadidentity.FromKubernetes("cluster.local", "documents", workloadidentity.DeliveryService)
	if carrier.Service != workloadidentity.DeliveryService || carrier.Module != "documents" {
		t.Fatalf("carrier = %+v", carrier)
	}
}
