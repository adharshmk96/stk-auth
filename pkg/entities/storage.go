package entities

type AccountStore interface {
	SaveUser(user *Account) error
	GetUserByUserID(email string) (*Account, error)
	GetUserByEmail(email string) (*Account, error)
	GetUserByUsername(username string) (*Account, error)
	SaveSession(session *Session) error
	GetSessionByID(sessionID string) (*Session, error)
	GetUserBySessionID(sessionID string) (*Account, error)
	InvalidateSessionByID(sessionID string) error
}
