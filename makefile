VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
MAJOR := $(shell echo $(VERSION) | cut -d . -f 1)
MINOR := $(shell echo $(VERSION) | cut -d . -f 2)
PATCH := $(shell echo $(VERSION) | cut -d . -f 3 | sed 's/v//')
NEW_PATCH := $(shell echo $$(($(PATCH) + 1)))
NEW_MINOR := $(shell echo $$(($(MINOR) + 1)))
NEW_MAJOR := $(shell echo $$(($(MAJOR) + 1)))
NEW_TAG_PATCH := $(MAJOR).$(MINOR).$(NEW_PATCH)
NEW_TAG_MINOR := $(MAJOR).$(NEW_MINOR).0
NEW_TAG_MAJOR := $(NEW_MAJOR).0.0

.PHONY: patch minor major build test publish keygen serve

##########################
### Manage Commands
##########################

patch:
	$(eval NEW_TAG := $(NEW_TAG_PATCH))
	$(call tag)

minor:
	$(eval NEW_TAG := $(NEW_TAG_MINOR))
	$(call tag)

major:
	$(eval NEW_TAG := $(NEW_TAG_MAJOR))
	$(call tag)

publish:
	@git push origin $(VERSION)

build:
	@go build .	

test:
	@go test -v ./... -coverprofile=coverage.out && go tool cover -html=coverage.out

serve:
	@go run . serve -p 8080

##########################
### Setup Commands
##########################

init: tidy migrate keygen
	@echo "Project initialized."

tidy:
	@echo "initializing go module"
	@go mod tidy > /dev/null

migrate:
	@echo "migrating database"
	@migdb up > /dev/null

keygen:
	@mkdir -p .keys
	@openssl genpkey -algorithm RSA -out .keys/private_key.pem -pkeyopt rsa_keygen_bits:2048
	@chmod 666 .keys/private_key.pem
	@openssl rsa -pubout -in .keys/private_key.pem -out .keys/public_key.pem
	@chmod 666 .keys/public_key.pem

##########################
### Helpers
##########################
define tag
	@echo "current version is $(VERSION)"
    $(eval EXISTING_TAG := $(shell git tag -l $(NEW_TAG) 2>/dev/null))
    @if [ "$(EXISTING_TAG)" = "$(NEW_TAG)" ]; then \
        echo "Tag $(NEW_TAG) already exists. reapplying the tag."; \
        git tag -d $(NEW_TAG); \
    fi
    $(call update_file)
    @git tag $(NEW_TAG)
    @echo "created new version $(NEW_TAG)."
endef

define update_file
    @echo "updating files to version $(NEW_TAG)"
    @sed -i.bak "s/var version = \"[^\"]*\"/var version = \"$(NEW_TAG)\"/g" ./cmd/root.go
    @rm cmd/root.go.bak
    @git add cmd/root.go
    @git commit -m "bump version to $(NEW_TAG)" > /dev/null
endef
