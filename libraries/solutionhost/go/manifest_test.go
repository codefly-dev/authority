package solutionhost_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/stretchr/testify/require"
)

func TestTheSpecShapeReadsAsWritten(t *testing.T) {
	manifest := valid(t)
	require.Equal(t, "acme.local.wiki", manifest.Binding)
	require.Equal(t, "wiki", manifest.Alias)
	require.Equal(t, solutionhost.KindModule, manifest.Kind)
	require.Equal(t, uint64(7), manifest.Generation)
	require.Equal(t, solutionhost.HostTarget{Coordinate: testCoordinate, Domain: testDomain}, manifest.Host)
	require.Equal(t, "obin/wiki@0.1.0", manifest.Release.Identity())
	require.Len(t, manifest.Workloads, 2)
	require.Equal(t, "http://localhost:5123", manifest.Endpoints[0].Address)
	require.Equal(t, []string{"modelservice.profiles:invoke"}, manifest.Authority.Bindings[0].Operations["headless"])
	require.Equal(t, solutionhost.PayloadDigest("sha256:0000000000000000000000000000000000000000000000000000000000000001"), manifest.Frontend.Payload.Digest)
}

// Every rule Validate holds, each driven by the one mutation that breaks it.
// The message is asserted too, so a refusal arriving from another rule does
// not pass for this one.
func TestValidateRefusesEachBrokenRule(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*solutionhost.ModuleManifest)
		want   string
	}{
		"binding reserved":            {func(m *solutionhost.ModuleManifest) { m.Binding = "base" }, "instance id"},
		"binding with a slash":        {func(m *solutionhost.ModuleManifest) { m.Binding = "acme/wiki" }, "instance id"},
		"alias is a path":             {func(m *solutionhost.ModuleManifest) { m.Alias = "wiki/pages" }, "one lowercase path segment"},
		"alias uppercase":             {func(m *solutionhost.ModuleManifest) { m.Alias = "Wiki" }, "one lowercase path segment"},
		"unknown kind":                {func(m *solutionhost.ModuleManifest) { m.Kind = "service" }, "kind"},
		"generation zero":             {func(m *solutionhost.ModuleManifest) { m.Generation = 0 }, "generation starts at 1"},
		"no coordinate":               {func(m *solutionhost.ModuleManifest) { m.Host.Coordinate = "" }, "host coordinate"},
		"no domain":                   {func(m *solutionhost.ModuleManifest) { m.Host.Domain = "" }, "host domain"},
		"publisher is a path":         {func(m *solutionhost.ModuleManifest) { m.Release.Publisher = "obin/x" }, "release publisher"},
		"version is a range":          {func(m *solutionhost.ModuleManifest) { m.Release.Version = "^0.1.0" }, "not semantic"},
		"no workload":                 {func(m *solutionhost.ModuleManifest) { m.Workloads, m.Endpoints = nil, nil }, "declares no workload"},
		"service twice":               {func(m *solutionhost.ModuleManifest) { m.Workloads[1].Service = "backend" }, "declared twice"},
		"no container":                {func(m *solutionhost.ModuleManifest) { m.Workloads[0].Container = "" }, "container"},
		"endpoint to no workload":     {func(m *solutionhost.ModuleManifest) { m.Endpoints[0].Service = "frontend" }, "no declared workload"},
		"endpoint without address":    {func(m *solutionhost.ModuleManifest) { m.Endpoints[0].Address = "" }, "address"},
		"endpoint address multi-line": {func(m *solutionhost.ModuleManifest) { m.Endpoints[0].Address = "http://a\nb" }, "address"},
		"endpoint address too long": {func(m *solutionhost.ModuleManifest) {
			m.Endpoints[0].Address = "http://" + strings.Repeat("a", solutionhost.EndpointAddressMaxBytes)
		}, "address"},
		"endpoint twice": {func(m *solutionhost.ModuleManifest) { m.Endpoints[1] = m.Endpoints[0] }, "declared twice"},
		"no principal":   {func(m *solutionhost.ModuleManifest) { m.Authority.Principal = "" }, "principal"},
		"binding id twice": {func(m *solutionhost.ModuleManifest) {
			m.Authority.Bindings = append(m.Authority.Bindings, m.Authority.Bindings[0])
		}, "declared twice"},
		"no audience":             {func(m *solutionhost.ModuleManifest) { m.Authority.Bindings[0].Audience = "" }, "audience"},
		"no operation":            {func(m *solutionhost.ModuleManifest) { m.Authority.Bindings[0].Operations = nil }, "requests no operation"},
		"unknown operation":       {func(m *solutionhost.ModuleManifest) { m.Authority.Bindings[0].Operations["admin"] = []string{"a:b"} }, "operation \"admin\""},
		"operation with no scope": {func(m *solutionhost.ModuleManifest) { m.Authority.Bindings[0].Operations["lookup"] = []string{} }, "requests no scope"},
		"scope without action": {func(m *solutionhost.ModuleManifest) {
			m.Authority.Bindings[0].Operations["invoke"] = []string{"modelservice"}
		}, "<resource kind>:<action>"},
		"scope twice": {func(m *solutionhost.ModuleManifest) {
			m.Authority.Bindings[0].Operations["invoke"] = []string{"a:b", "a:b"}
		}, "twice"},
		"queue twice":          {func(m *solutionhost.ModuleManifest) { m.Authority.Queues = []string{"q", "q"} }, "queue \"q\" twice"},
		"blank namespace":      {func(m *solutionhost.ModuleManifest) { m.Authority.Namespaces = []string{""} }, "namespace"},
		"resource kind spaced": {func(m *solutionhost.ModuleManifest) { m.Authority.ResourceKinds = []string{"wiki pages"} }, "resource kind"},
		"group on a module": {func(m *solutionhost.ModuleManifest) {
			m.Group = &solutionhost.SolutionGroup{ID: "knowledge", Title: "Knowledge"}
		}, "a module is grouped by nothing"},
		"frontend contract 0":   {func(m *solutionhost.ModuleManifest) { m.Frontend.HostContract = 0 }, "host_contract"},
		"frontend payload hash": {func(m *solutionhost.ModuleManifest) { m.Frontend.Payload.Digest = "md5:x" }, "payload.digest"},
	} {
		t.Run(name, func(t *testing.T) {
			manifest := valid(t)
			tc.change(manifest)
			err := manifest.Validate()
			require.ErrorIs(t, err, solutionhost.ErrInvalid)
			require.ErrorContains(t, err, tc.want)
			_, err = manifest.CanonicalBytes()
			require.ErrorIs(t, err, solutionhost.ErrInvalid, "an invalid manifest has no canonical encoding")
			_, err = solutionhost.Marshal(manifest)
			require.ErrorIs(t, err, solutionhost.ErrInvalid, "an invalid manifest is never written")
		})
	}
}

func TestASolutionMayBeGroupedAndAuthorityIsOptional(t *testing.T) {
	manifest := valid(t)
	manifest.Kind = solutionhost.KindSolution
	manifest.Group = &solutionhost.SolutionGroup{ID: "knowledge", Title: "Knowledge", Order: 2}
	manifest.Authority = nil
	require.NoError(t, manifest.Validate())
}

// A withdrawal is identity only: it says the binding is gone and nothing about
// what ran, so no half of it can be read as still live.
func TestAWithdrawalCarriesOnlyItsIdentity(t *testing.T) {
	require.NoError(t, removed(t).Validate())
	for name, change := range map[string]func(*solutionhost.ModuleManifest){
		"workloads": func(m *solutionhost.ModuleManifest) { m.Workloads = valid(t).Workloads },
		"endpoints": func(m *solutionhost.ModuleManifest) { m.Endpoints = valid(t).Endpoints },
		"authority": func(m *solutionhost.ModuleManifest) { m.Authority = valid(t).Authority },
		"frontend":  func(m *solutionhost.ModuleManifest) { m.Frontend = valid(t).Frontend },
		"group":     func(m *solutionhost.ModuleManifest) { m.Group = &solutionhost.SolutionGroup{ID: "g", Title: "G"} },
	} {
		t.Run(name, func(t *testing.T) {
			manifest := removed(t)
			change(manifest)
			err := manifest.Validate()
			require.ErrorIs(t, err, solutionhost.ErrInvalid)
			require.ErrorContains(t, err, "is removed and declares "+name)
		})
	}
	// Its identity is still held: a withdrawal of nothing names nothing.
	manifest := removed(t)
	manifest.Alias = ""
	require.ErrorIs(t, manifest.Validate(), solutionhost.ErrInvalid)
}

// The documents the manifest replaced are refused by schema, with the remedy,
// whatever version they carry — never read as a manifest, never as malformed.
func TestReplacedDocumentsAreRefusedWithTheRemedy(t *testing.T) {
	for _, schema := range []string{
		"codefly/solution-host-binding/v1", "codefly/solution-host-binding/v2", "codefly/solution-host-binding/v4",
		"codefly/solution-authority/v1", "codefly/solution-authority/v4",
		"codefly/endpoint-delivery/v1", "codefly/endpoint-delivery/v4",
	} {
		t.Run(schema, func(t *testing.T) {
			document := strings.Replace(validYAML, solutionhost.SchemaModuleManifestV1, schema, 1) + "ownership_domain: obin\n"
			_, err := solutionhost.Parse([]byte(document))
			require.ErrorIs(t, err, solutionhost.ErrSchema)
			require.ErrorContains(t, err, "re-render it with a current Codefly CLI")
		})
	}
	for _, schema := range []string{"", "codefly/module-manifest/v2", "codefly/module-contract/v1"} {
		_, err := solutionhost.Parse([]byte(strings.Replace(validYAML, solutionhost.SchemaModuleManifestV1, schema, 1)))
		require.ErrorIs(t, err, solutionhost.ErrSchema)
		require.NotContains(t, err.Error(), "re-render")
	}
}

func TestDecodingIsStrict(t *testing.T) {
	for name, document := range map[string]string{
		"unknown field":         validYAML + "approved_builds: []\n",
		"build field on a host": strings.Replace(validYAML, "domain: obin}", "domain: obin, component: wiki}", 1),
		"repeated key":          validYAML + "alias: other\n",
		"explicit null":         validYAML + "group: ~\n",
		"merge key":             strings.Replace(validYAML, "host: {", "host: {<<: {}, ", 1),
		"fractional generation": strings.Replace(validYAML, "generation: 7", "generation: 7.5", 1),
		"two documents":         validYAML + "---\n" + validYAML,
		"frontend order in hex": strings.Replace(validYAML, "order: 10", "order: 0x0a", 1),
		"too large":             validYAML + "# " + strings.Repeat("x", solutionhost.ManifestMaxBytes) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := solutionhost.Parse([]byte(document))
			require.ErrorIs(t, err, solutionhost.ErrInvalid)
		})
	}
}

// The canonical bytes depend on what the manifest says, never on the order a
// producer emitted its sets in, and they read back as themselves.
func TestTheCanonicalEncodingIsOrderFreeAndRoundTrips(t *testing.T) {
	manifest := valid(t)
	want, err := manifest.CanonicalBytes()
	require.NoError(t, err)

	shuffled := valid(t)
	shuffled.Workloads[0], shuffled.Workloads[1] = shuffled.Workloads[1], shuffled.Workloads[0]
	shuffled.Endpoints[0], shuffled.Endpoints[1] = shuffled.Endpoints[1], shuffled.Endpoints[0]
	invoke := shuffled.Authority.Bindings[0].Operations["invoke"]
	invoke[0], invoke[1] = invoke[1], invoke[0]
	shuffled.Authority.Queues = []string{"z.queue", "wiki.index"}
	manifest.Authority.Queues = []string{"wiki.index", "z.queue"}
	want, err = manifest.CanonicalBytes()
	require.NoError(t, err)
	got, err := shuffled.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))

	// The canonical JSON is itself a manifest, and canonical.
	reread, err := solutionhost.ManifestFromVerified(want)
	require.NoError(t, err)
	again, err := reread.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, string(want), string(again))

	// The writer's YAML reads back as the same document.
	written, err := solutionhost.Marshal(shuffled)
	require.NoError(t, err)
	parsed, err := solutionhost.Parse(written)
	require.NoError(t, err)
	before, err := shuffled.Digest()
	require.NoError(t, err)
	after, err := parsed.Digest()
	require.NoError(t, err)
	require.Equal(t, before, after)

	// And the digest moves when, and only when, the manifest does.
	parsed.Endpoints[0].Address = "http://localhost:6000"
	moved, err := parsed.Digest()
	require.NoError(t, err)
	require.NotEqual(t, before, moved)
}

func TestANonCanonicalPayloadIsRefusedEvenWhenItParses(t *testing.T) {
	_, err := solutionhost.ManifestFromVerified([]byte(validYAML))
	require.ErrorIs(t, err, solutionhost.ErrNotCanonical)
	canonical, err := valid(t).CanonicalBytes()
	require.NoError(t, err)
	_, err = solutionhost.ManifestFromVerified(append(canonical, ' '))
	require.ErrorIs(t, err, solutionhost.ErrNotCanonical)
}

// A workload is found by the service a credential names; a withdrawn binding
// runs nothing.
func TestTheWorkloadIsFoundByItsService(t *testing.T) {
	manifest := valid(t)
	workload, found := manifest.WorkloadNamed("indexer")
	require.True(t, found)
	require.Equal(t, "indexer", workload.Service)
	_, found = manifest.WorkloadNamed("frontend")
	require.False(t, found)
	_, found = removed(t).WorkloadNamed("backend")
	require.False(t, found, "a withdrawn binding runs nothing")
}

// The standalone frontend file is the authored half: the renderer's payload
// is a field it does not declare, and the block's own rules apply.
func TestTheStandaloneFrontendIsTheAuthoredHalf(t *testing.T) {
	frontend, err := solutionhost.ParseFrontend([]byte("title: Wiki\norder: 0\nexposed_module: ./Page\nhost_contract: 1\n"))
	require.NoError(t, err)
	require.Equal(t, "Wiki", frontend.Title)
	for name, document := range map[string]string{
		"payload":        "title: Wiki\norder: 0\nexposed_module: ./Page\nhost_contract: 1\npayload: {artifact: a, digest: d, media_type: m}\n",
		"order omitted":  "title: Wiki\nexposed_module: ./Page\nhost_contract: 1\n",
		"contract zero":  "title: Wiki\norder: 0\nexposed_module: ./Page\nhost_contract: 0\n",
		"multi-line":     "title: \"Wi\\nki\"\norder: 0\nexposed_module: ./Page\nhost_contract: 1\n",
		"empty document": "",
	} {
		_, err := solutionhost.ParseFrontend([]byte(document))
		require.ErrorIs(t, err, solutionhost.ErrInvalid, name)
	}
}

// A frontend declaration or a manifest that is a list, or a bare scalar, is
// refused as what it is, naming the declaration, rather than decoded into an
// empty value whose first missing field would be blamed.
func TestADocumentThatIsNotAMappingIsRefusedAsSuch(t *testing.T) {
	for name, data := range map[string]string{"a list": "- title: Notes\n", "a scalar": "notes\n"} {
		if _, err := solutionhost.ParseFrontend([]byte(data)); err == nil || !errors.Is(err, solutionhost.ErrInvalid) ||
			!strings.Contains(err.Error(), "frontend declaration") || !strings.Contains(err.Error(), "not a mapping") {
			t.Errorf("a frontend that is %s: got %v", name, err)
		}
	}
}
