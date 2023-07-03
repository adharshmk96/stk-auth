package entities

import "github.com/golang-jwt/jwt/v5"

type CustomClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

type AccountService interface {
	CreateUser(user *Account) (*Account, error)
	Authenticate(login *Account) error
	ChangePassword(user *Account) error
	GetUserByID(userId string) (*Account, error)
	CreateSession(user *Account) (*Session, error)
	GetUserBySessionId(sessionId string) (*Account, error)
	GenerateJWT(claims *CustomClaims) (string, error)
	ValidateJWT(token string) (*CustomClaims, error)
	LogoutUserBySessionId(sessionId string) error
}
