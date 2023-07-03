package entities

type AccountStore interface {
	// Create
	SaveUser(user *Account) error
	SaveSession(session *Session) error
	// Read
	GetUserByUserID(email string) (*Account, error)
	GetUserByEmail(email string) (*Account, error)
	GetUserByUsername(username string) (*Account, error)
	GetSessionByID(sessionID string) (*Session, error)
	GetUserBySessionID(sessionID string) (*Account, error)
	// Update
	InvalidateSessionByID(sessionID string) error
	UpdateUserByID(user *Account) error
}
