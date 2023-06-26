package storage

import "github.com/adharshmk96/stk-auth/pkg/entities"

type AccountStore interface {
	SaveUser(user *entities.Account) error
	GetUserByEmail(email string) (*entities.Account, error)
	GetUserByUsername(username string) (*entities.Account, error)
	SaveSession(session *entities.Session) error
	GetSessionByID(sessionID string) (*entities.Session, error)
	GetUserBySessionID(sessionID string) (*entities.Account, error)
}
