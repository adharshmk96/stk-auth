VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
MAJOR := $(shell echo $(VERSION) | cut -d . -f 1 | sed 's/v//')
MINOR := $(shell echo $(VERSION) | cut -d . -f 2)
PATCH := $(shell echo $(VERSION) | cut -d . -f 3)
NEW_PATCH := $(shell echo $$(($(PATCH) + 1)))
NEW_MINOR := $(shell echo $$(($(MINOR) + 1)))
NEW_MAJOR := $(shell echo $$(($(MAJOR) + 1)))
NEW_TAG_PATCH := v$(MAJOR).$(MINOR).$(NEW_PATCH)
NEW_TAG_MINOR := v$(MAJOR).$(NEW_MINOR).0
NEW_TAG_MAJOR := v$(NEW_MAJOR).0.0

.PHONY: patch minor major build test publish keygen serve init initci moddownload migrate

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

testci:
	@go test ./... -coverprofile=coverage.out

clean-branch:
	@git branch --merged | egrep -v "(^\*|main|master)" | xargs git branch -d

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

##########################
### Setup Commands
##########################

init: moddownload migrate keygen
	@echo "Project initialized."

initci: moddownload keygen
	@echo "Project initialized for CI."

serve:
	@go run . serve -p 8080

moddownload:
	@echo "initializing go module"
	@go mod download > /dev/null

migrate:
	@go run . migrate

keygen:
	@mkdir -p .keys
	@openssl genpkey -algorithm RSA -out .keys/private_key.pem -pkeyopt rsa_keygen_bits:2048
	@chmod 666 .keys/private_key.pem
	@openssl rsa -pubout -in .keys/private_key.pem -out .keys/public_key.pem
	@chmod 666 .keys/public_key.pem

##########################
### Clean up commands
##########################

clean:
	@rm -rf .keys
	@rm -f auth_database.db
	@rm -f coverage.out
	
##########################
### STK Stuff
##########################

mkdocs:
	@python ./scripts/docgen.py