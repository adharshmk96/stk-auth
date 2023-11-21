publish:
	@git push && semver push


##########################
### Build Commands
##########################

BINARY_NAME=stkAuth

build:
	@go build -o ./out/$(BINARY_NAME) -v

run: 
	@go run . serve -p 8080

test:
	@go test ./...

coverage:
	@go test -v ./... -coverprofile=coverage.out 
	@go tool cover -html=coverage.out

testci:
	@go test ./... -coverprofile=coverage.out

clean:
	@go clean
	@rm -f ./out/$(BINARY_NAME)
	@rm -f coverage.out

deps:
	@go mod download

tidy:
	@go mod tidy

lint:
	@golangci-lint run --enable-all

vet:
	@go vet

clean-branch:
	@git branch | egrep -v "(^\*|main|master)" | xargs git branch -D
	@git tag -d $(shell git tag -l)

	
##########################
### Setup Commands
##########################

init: 
	@go mod tidy
# Install tools
	@go install github.com/adharshmk96/semver@latest
	@go install github.com/vektra/mockery/v2@latest
# Setup Git hooks
	@git config core.hooksPath .githooks

# mockgen:
	@rm -rf ./mocks
	@mockery --all	

	@echo "Project initialized."
