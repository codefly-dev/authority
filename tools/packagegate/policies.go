package packagegate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/codefly-dev/core/composition"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"gopkg.in/yaml.v3"

	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
)

// policyExtension is the OpenAPI operation extension a route declares its
// policy with, the authority.hop.v1.Policy a proto method marks itself with.
const policyExtension = "x-codefly-authority-policy"

// undeclared lists, sorted, the published methods of the module at dir that a
// host fronting the module receives with no policy: each served procedure of a
// protobuf contract, each google.api.http route of one, and each operation of
// an OpenAPI contract. It reads them the way the CLI's delivery does
// (codefly-dev/cli pkg/methodpolicy, gitops.HostMethodPolicies): a route the
// REST gateway renders from a proto method carries that method's policy, and
// a service that stands in for a host is left out, since a host that
// implements the interfaces it implements never runs it.
func undeclared(dir string, manifest *composition.PackageManifest, catalog *composition.APIContractCatalog, identities []string) ([]string, error) {
	standIns, err := hostStandIns(dir, identities)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, service := range manifest.Services {
		if standIns[service.Name] {
			continue
		}
		contracts := slices.Clone(service.APIContracts)
		// The proto first: an OpenAPI route it binds inherits its policy.
		sort.SliceStable(contracts, func(i, j int) bool {
			return contracts[i].Kind == composition.APIContractKindProtobuf && contracts[j].Kind != composition.APIContractKindProtobuf
		})
		declared := map[string]bool{}
		for _, contract := range contracts {
			methods, err := contractPolicies(dir, catalog, service.Name, contract)
			if err != nil {
				return nil, err
			}
			for method, declares := range methods {
				declared[method] = declared[method] || declares
			}
		}
		for method, declares := range declared {
			if !declares {
				missing = append(missing, service.Name+": "+method)
			}
		}
	}
	sort.Strings(missing)
	return missing, nil
}

// hostStandIns are the services that stand in for a host: they run as no
// module identity and export an endpoint implementing a Codefly interface, so
// a host implementing it never runs them (the local authority on a saas host).
func hostStandIns(dir string, identities []string) (map[string]bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "module.codefly.yaml"))
	if err != nil {
		return nil, err
	}
	var module struct {
		Interface struct {
			Endpoints []struct {
				Service    string   `yaml:"service"`
				Implements []string `yaml:"implements"`
			} `yaml:"endpoints"`
		} `yaml:"interface"`
	}
	if err := yaml.Unmarshal(data, &module); err != nil {
		return nil, err
	}
	standIns := map[string]bool{}
	for _, endpoint := range module.Interface.Endpoints {
		if len(endpoint.Implements) > 0 && !slices.Contains(identities, endpoint.Service) {
			standIns[endpoint.Service] = true
		}
	}
	return standIns, nil
}

// contractPolicies maps each method one contract publishes to whether it
// declares a policy.
func contractPolicies(dir string, catalog *composition.APIContractCatalog, service string, contract composition.ProvidedAPIContract) (map[string]bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(contract.Path)))
	if err != nil {
		return nil, err
	}
	switch contract.Kind {
	case composition.APIContractKindProtobuf:
		return protoPolicies(data, served(catalog, service, contract.Endpoint))
	case composition.APIContractKindOpenAPI:
		return routePolicies(data)
	}
	return nil, nil
}

// served is the set of procedures the catalog records for an endpoint.
func served(catalog *composition.APIContractCatalog, service, endpoint string) map[string]bool {
	procedures := map[string]bool{}
	for _, e := range catalog.Endpoints {
		if e.Service == service && e.Endpoint == endpoint {
			for _, s := range e.Services {
				for _, p := range s.Procedures {
					procedures[p] = true
				}
			}
		}
	}
	return procedures
}

func protoPolicies(data []byte, procedures map[string]bool) (map[string]bool, error) {
	var set descriptorpb.FileDescriptorSet
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).Unmarshal(data, &set); err != nil {
		return nil, err
	}
	methods := map[string]bool{}
	for _, file := range set.GetFile() {
		for _, service := range file.GetService() {
			for _, method := range service.GetMethod() {
				procedure := "/" + strings.TrimPrefix(file.GetPackage()+"."+service.GetName(), ".") + "/" + method.GetName()
				if !procedures[procedure] {
					continue
				}
				policy, _ := proto.GetExtension(method.GetOptions(), hopv1.E_Policy).(*hopv1.Policy)
				declares := policy.GetAnyCheckedCaller() || len(policy.GetRequires()) > 0
				methods[procedure] = declares
				for _, route := range httpRoutes(method.GetOptions()) {
					methods[route] = declares
				}
			}
		}
	}
	return methods, nil
}

func routePolicies(data []byte) (map[string]bool, error) {
	var document struct {
		BasePath string                                           `json:"basePath"`
		Paths    map[string]map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	methods := map[string]bool{}
	for path, operations := range document.Paths {
		for verb, operation := range operations {
			switch verb {
			case "get", "put", "post", "delete", "patch", "head", "options":
				_, declares := operation[policyExtension]
				methods[strings.ToUpper(verb)+" "+strings.TrimSuffix(document.BasePath, "/")+path] = declares
			}
		}
	}
	return methods, nil
}

// httpRoutes are the "<VERB> <template>" routes a method's google.api.http
// option binds it to.
func httpRoutes(options *descriptorpb.MethodOptions) []string {
	rule, ok := proto.GetExtension(options, annotations.E_Http).(*annotations.HttpRule)
	if !ok || rule == nil {
		return nil
	}
	var routes []string
	for _, r := range append([]*annotations.HttpRule{rule}, rule.GetAdditionalBindings()...) {
		var verb, template string
		switch pattern := r.GetPattern().(type) {
		case *annotations.HttpRule_Get:
			verb, template = "GET", pattern.Get
		case *annotations.HttpRule_Put:
			verb, template = "PUT", pattern.Put
		case *annotations.HttpRule_Post:
			verb, template = "POST", pattern.Post
		case *annotations.HttpRule_Delete:
			verb, template = "DELETE", pattern.Delete
		case *annotations.HttpRule_Patch:
			verb, template = "PATCH", pattern.Patch
		case *annotations.HttpRule_Custom:
			verb, template = strings.ToUpper(pattern.Custom.GetKind()), pattern.Custom.GetPath()
		}
		if verb != "" {
			routes = append(routes, verb+" "+template)
		}
	}
	return routes
}

func undeclaredError(missing []string) error {
	return fmt.Errorf("a host fronting the module receives these published methods with no policy (mark each with authority.hop.v1.policy):\n  %s", strings.Join(missing, "\n  "))
}
