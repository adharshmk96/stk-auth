# stk-auth

A simple authentication server written in go with basic features.

## Usage

Binary can be downloaded from releases

```bash
stk-auth serve -p 8080
```

## Development

refer [dev docs](docs/dev.md) for general overview

References.
- [server](docs/server.md)
- [account services](docs/services/account.md)
- [storage](docs/storage/storage.md)
- [sqlite storage](docs/storage/sqlite.md)


## About

This server uses 
- cobra for cli
- stk for server framework
- postman for api tests
- migdb for migrations

