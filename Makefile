CODEFLY ?= codefly
GO_MODULES := $(sort $(patsubst %/go.mod,%,$(shell git ls-files '*/go.mod')))
ROLE_PLAN := github.com/codefly-dev/authority/libraries/authority-core/go/roleplan
export GOWORK := off

.PHONY: verify unit role-plan playground-check scenarios

verify: unit role-plan playground-check scenarios

# The two client implementations that reserve hop admissions in Postgres must
# exercise the same real transport regression as the hosted Go/Python jobs.
unit:
	@test -n "$$HOP_TEST_POSTGRES" || { echo "HOP_TEST_POSTGRES must name a disposable PostgreSQL database for the Go and Python hop tests" >&2; exit 1; }
	@set -eu; for module in $(GO_MODULES); do \
		echo "Checking $$module"; \
		(cd "$$module" && go vet ./... && \
		 packages=$$(go list ./...) && \
		 packages=$$(printf '%s\n' "$$packages" | awk '$$0 != "$(ROLE_PLAN)"') && \
		 test -n "$$packages" && go test -race -count=1 $$packages); \
	done
	cd libraries/authority-core/go && go test -count=1 -run '^TestReachOfIsFastOnDenseCompositions$$' ./decide
	cd libraries/authority-client/python && uv run --isolated --with . --with pytest --with asyncpg python -m pytest -q
	cd libraries/authority-client/typescript && npm ci && npm test

role-plan:
	cd libraries/authority-core/go && go test -race -count=1 ./roleplan

playground-check:
	cd modules/authority/services/edge/web && npm ci && npm run check:bundle
	cd playground && $(CODEFLY) config generate documents-collection-cursor SIGNING_KEY && $(CODEFLY) doctor workspace

scenarios:
	cd libraries/scenario/go && CODEFLY_BINARY="$(CODEFLY)" go test -race -tags composition -count=1 -timeout 20m ./playground
