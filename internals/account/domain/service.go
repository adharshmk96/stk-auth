package domain

// Service
type AccountService interface {
	CreateAccount(account *Account) error
	GetAccountByEmail(email string) (*Account, error)

	// Session
	StartSession(account *Account) (*Session, error)
	EndSession(session string) error
	GetSessionAccount(sessionId string) (*Account, error)
}
