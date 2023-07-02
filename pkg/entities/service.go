package entities

type AccountService interface {
	RegisterUser(user *Account) (*Account, error)
	ValidateLogin(login *Account) error
	LoginUserSession(user *Account) (*Session, error)
	GenerateJWT(user *Account, session *Session) (string, error)
	GetUserBySessionId(sessionId string) (*Account, error)
	GetUserBySessionToken(sessionToken string) (*AccountWithToken, error)
	LogoutUserBySessionId(sessionId string) error
	LogoutUserBySessionToken(sessionToken string) error
}
