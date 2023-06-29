# Development

[back to main](../README.md)

This document describes the development setup.

## Requirements
- [go](https://golang.org/)
- [migdb](https://github.com/adharshmk96/migdb) (db migrations)
- [make](https://www.gnu.org/software/make/) or [mingw](http://www.mingw.org/) (for windows)
- [vscode](https://code.visualstudio.com/) (reccommended)
- [postman](https://www.postman.com/) (optional)

## Initialize and Run

- Initialize (jwt keys, db, go modules, etc...)

```bash
make init
```

- Run the server
  
```bash
make serve
```

## Debugging

A vscode launch configuration is added to debug the server. Use the `serve in port 8080` configuration to debug the server.

TIP: Set breakpoints and press `F5` to start debugging.

## Managing Version & Release

Github Actions are set to automatically publish the release to github. It uses the tag name as the release version.

> There are pre-written commands in makefile to manage the version and release. Refer the `Makefile` for more details.

### pre-release commands

- patch : `make patch`
- minor : `make minor`
- major : `make major`

### release commands

- publish : `make publish`


## Server

an instance of stk framework is used to setup the server, refer the server directory to find the usage.

### Configuration
`pkg\infra\config` contains the configuration for the server. Add your configuration logic here

### Routing
`server\routing.go` contains the routing logic for the server.

### Middleware
`server\middleware.go` contains the middlewares for the server.



