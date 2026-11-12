# policy-management — GPU network access-control operator for Bridge
IMG ?= ghcr.io/armadasystems/policy-management:latest
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.15.0

.PHONY: all build test fmt vet tidy generate manifests docker-build install deploy run

all: fmt vet build

tidy:
	go mod tidy

# Regenerate DeepCopy methods from the API markers (replaces the scaffold file).
generate:
	$(CONTROLLER_GEN) object:headerFile="" paths="./api/..."

# Regenerate the CRD + RBAC manifests from the kubebuilder markers.
manifests:
	$(CONTROLLER_GEN) crd rbac:roleName=policy-management-role paths="./..." output:crd:artifacts:config=config/crd/bases

build:
	go build -o bin/manager ./cmd

run:
	go run ./cmd

test:
	go test ./... -count=1

fmt:
	go fmt ./...

vet:
	go vet ./...

docker-build:
	docker build -t $(IMG) .

# Apply the CRD, then the controller (edit config/ for your cluster first).
install:
	kubectl apply -f config/crd/bases/policy.bridge.armada.ai_accesspolicies.yaml

sample:
	kubectl apply -f config/samples/accesspolicy_coding_pilot.yaml
