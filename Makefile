build: build_linux_amd64

build_linux_amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ssh-audit cmd/ssh-audit/main.go

