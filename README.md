# auth-server

A simple authentication server written in go with basic features.

## Usage

```bash
server serve -p 8080
```

## Development

### With sqlite3 ( default db )

- clone the repository 
```git clone https://github.com/adharshmk96/auth-server.git```
- install dependancies
```go mod tidy```
- run migrations using migdb ( install migdb `go install github.com/adharshmk96/migdb` )
```migdb up``` 
- debugging, you can use launch.json to debug the server in vscode.
- postman collection is available in the repo for api testing.

## About

This server uses 
- cobra for cli
- stk for server framework
- postman for api tests
- migdb for migrations

