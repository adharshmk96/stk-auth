package entities

import "github.com/golang-jwt/jwt/v5"

type CustomClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

type TokenService interface {
	GenerateJWT(claims *CustomClaims) (string, error)
	ValidateJWT(token string) (*CustomClaims, error)
}
type AccountService interface {
	CreateUser(user *Account) (*Account, error)
	Authenticate(login *Account) error
	ChangePassword(user *Account) error
	GetUserByID(userId string) (*Account, error)
}

type SessionService interface {
	CreateSession(user *Account) (*Session, error)
	GetUserBySessionId(sessionId string) (*Account, error)
	LogoutUserBySessionId(sessionId string) error
}

type GroupService interface {
	// CreateGroup(group *UserGroup) (*UserGroup, error)
	// GetGroupByID(groupId string) (*UserGroup, error)
	// UpdateGroupByID(group *UserGroup) error
	// DeleteGroupByID(groupId string) error
	// AddUserToGroup(userId string, groupId string) error
}

type UserManagementService interface {
	AccountService
	SessionService
	GroupService
	TokenService
}
