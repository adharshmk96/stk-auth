# Development

[back to main](../README.md)

This document describes the development setup.

## Requirements
- make
- go
- vscode

## Initial Run

- Generate jwt keys

```bash
make init
```

- Run the server
  
```bash
make serve
```

## Managing

Version management is done using `make` and `git tags`. Refer the `Makefile` for more details.

pre-release commands

- patch : `make patch`
- minor : `make minor`
- major : `make major`

release commands

- publish : `make publish`


## Server

an instance of stk framework is used to setup the server, refer the server directory to find the usage.

### Configuration
`pkg\infra\config` contains the configuration for the server. Add your configuration logic here

### Routing
`server\routing.go` contains the routing logic for the server.

### Middleware
`server\middleware.go` contains the middlewares for the server.



