package domain

// Storage
type AccountStorage interface {
	// Account
	StoreAccount(account *Account) error
	GetAccountByEmail(email string) (*Account, error)

	// Session
	StoreSession(session *Session) error
	GetSessionByID(id string) (*Session, error)
	UpdateSession(session *Session) error
	GetAccountBySessionID(id string) (*Account, error)
}
