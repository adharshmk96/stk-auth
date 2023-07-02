package entities

import "github.com/golang-jwt/jwt/v5"

type CustomClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	jwt.RegisteredClaims
}

type AccountService interface {
	RegisterUser(user *Account) (*Account, error)
	ValidateLogin(login *Account) error
	LoginUserSession(user *Account) (*Session, error)
	GenerateJWT(user *Account, session *Session) (string, error)
	ValidateJWT(token string) (*CustomClaims, error)
	GetUserBySessionId(sessionId string) (*Account, error)
	GetUserBySessionToken(sessionToken string) (*AccountWithToken, error)
	LogoutUserBySessionId(sessionId string) error
	LogoutUserBySessionToken(sessionToken string) error
}
