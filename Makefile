all: test vet build

test:
	go test -v ./...

vet:
	go vet ./...

build:
	go build -o bin/spf ./cmd/spf/main.go
