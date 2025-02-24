DYNAMIC_REGO_FOLDER=./checks/kubernetes/policies/dynamic
BUNDLE_FILE=bundle.tar.gz
REGISTRY_PORT=5111
TEMP_DIR := ./.tmp

# Command templates #################################
GOIMPORTS_CMD := $(TEMP_DIR)/gosimports -local github.com/khulnasoft

# Tool versions #################################
GOSIMPORTS_VERSION := v0.3.8
GOLICENSES_VERSION := v5.0.1

# Formatting variables #################################
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# Paths #################################
OPA_CMD := ./cmd/opa
REGAL_CONFIG := .regal/config.yaml
REGAL_RULES := .regal/rules

## Bootstrapping targets #################################

.PHONY: bootstrap
bootstrap: $(TEMP_DIR) bootstrap-go bootstrap-tools ## Download and install all tooling dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMP_DIR)
	GO111MODULE=on GOBIN=$(realpath $(TEMP_DIR)) go get -u golang.org/x/perf/cmd/benchstat
	curl -sSfL https://raw.githubusercontent.com/khulnasoft/go-licenses/master/golicenses.sh | sh -s -- -b $(TEMP_DIR)/ $(GOLICENSES_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)

.PHONY: test
test:
	go test -v ./...

.PHONY: static-analysis
static-analysis: check-go-mod-tidy check-licenses  ## Run all static analysis checks

.PHONY: check-licenses
check-licenses:  ## Ensure transitive dependencies are compliant with the current license policy
	$(call title,Checking for license compliance)
	$(TEMP_DIR)/golicenses check ./...

.PHONY: check-go-mod-tidy
check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

.PHONY: integration-test
integration-test:
	go test -v -timeout 5m -tags=integration ./integration/...

.PHONY: rego
rego: fmt-rego check-rego lint-rego test-rego docs

.PHONY: fmt-rego
fmt-rego:
	go run $(OPA_CMD) fmt -w lib/ checks/ examples/ $(REGAL_RULES)

.PHONY: test-rego
test-rego:
	go run $(OPA_CMD) test --explain=fails lib/ checks/ examples/ --ignore '*.yaml'

.PHONY: check-rego
check-rego:
	@go run $(OPA_CMD) check lib checks --v0-v1 --strict

.PHONY: lint-rego
lint-rego: check-rego
	@regal test $(REGAL_RULES)
	@regal lint lib checks \
		--config-file $(REGAL_CONFIG) \
		--enable deny-rule,naming-convention \
		--timeout 5m

.PHONY: bundle
bundle: create-bundle verify-bundle

.PHONY: id
id:
	@go run ./cmd/id

.PHONY: command-id
command-id:
	@go run ./cmd/command_id

.PHONY: outdated-api-updated
outdated-api-updated:
	sed -i.bak "s|recommendedVersions :=.*|recommendedVersions := $(OUTDATE_API_DATA)|" $(DYNAMIC_REGO_FOLDER)/outdated_api.rego && rm $(DYNAMIC_REGO_FOLDER)/outdated_api.rego.bak

.PHONY: docs
docs: fmt-examples
	go run ./cmd/avd_generator

.PHONY: docs-test
docs-test:
	go test -v ./cmd/avd_generator/...

.PHONY: create-bundle
create-bundle:
	./scripts/bundle.sh

.PHONY: verify-bundle
verify-bundle:
	cp $(BUNDLE_FILE) scripts/$(BUNDLE_FILE)
	cd scripts && go run verify-bundle.go
	rm scripts/$(BUNDLE_FILE)

.PHONY: build-opa
build-opa:
	go build $(OPA_CMD)

.PHONY: fmt-examples
fmt-examples:
	go run ./cmd/fmt-examples

.PHONY: start-registry
start-registry:
	docker run --rm -it -d -p ${REGISTRY_PORT}:5000 --name registry registry:2 

.PHONY: stop-registry
stop-registry:
	docker stop registry

.PHONY: push-bundle
push-bundle: create-bundle
	@REPO=localhost:${REGISTRY_PORT}/tunnel-audit:latest ;\
	echo "Pushing to repository: $$REPO" ;\
	docker run --rm -it --net=host -v $$PWD/${BUNDLE_FILE}:/${BUNDLE_FILE} bitnami/oras:latest push \
		$$REPO \
		 --artifact-type application/vnd.cncf.openpolicyagent.config.v1+json \
		"$(BUNDLE_FILE):application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
