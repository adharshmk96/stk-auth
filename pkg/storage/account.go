package storage

import "github.com/adharshmk96/auth-server/pkg/entities"

type AccountStore interface {
	SaveUser(user *entities.Account) error
	GetUserByEmail(email string) (*entities.Account, error)
	GetUserByUsername(username string) (*entities.Account, error)
	SaveSession(session *entities.Session) error
	RetrieveSessionByID(sessionID string) (*entities.Session, error)
}
