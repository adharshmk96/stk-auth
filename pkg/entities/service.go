package entities

import "github.com/golang-jwt/jwt/v5"

type CustomClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	jwt.RegisteredClaims
}

type AccountService interface {
	CreateUser(user *Account) (*Account, error)
	Authenticate(login *Account) error
	CreateSession(user *Account) (*Session, error)
	GenerateJWT(claims *CustomClaims) (string, error)
	ValidateJWT(token string) (*CustomClaims, error)
	GetUserBySessionId(sessionId string) (*Account, error)
	LogoutUserBySessionId(sessionId string) error
}
