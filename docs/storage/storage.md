# Storage interface

[back to main](../../README.md)

This document describes the storage interface.

Storage Interfaces are defined in the `storage` package. in the `storage.go` file.

## AccountStore

```go
type AccountStore interface {
	SaveUser(user *entities.Account) error
	GetUserByUserID(email string) (*entities.Account, error)
	GetUserByEmail(email string) (*entities.Account, error)
	GetUserByUsername(username string) (*entities.Account, error)
	SaveSession(session *entities.Session) error
	GetSessionByID(sessionID string) (*entities.Session, error)
	GetUserBySessionID(sessionID string) (*entities.Account, error)
	InvalidateSessionByID(sessionID string) error
}
```

