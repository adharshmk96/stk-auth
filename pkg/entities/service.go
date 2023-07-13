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

	// For Admin
	// GetUserList() ([]*Account, error)
	// UpdateUser(user *Account) error
	// DeleteUser(userId string) error
}

type SessionService interface {
	CreateSession(user *Account) (*Session, error)
	GetUserBySessionId(sessionId string) (*Account, error)
	LogoutUserBySessionId(sessionId string) error
}

type GroupService interface {
	CreateGroup(group *UserGroup) (*UserGroup, error)
	GetGroupsByUserID(userId UserID) ([]*UserGroup, error)
	UpdateGroupByID(group *UserGroup) error
	DeleteGroupByID(groupId string) error
	AddUserToGroup(userId UserID, groupId string) error
	RemoveUserFromGroup(userId UserID, groupId string) error
	CheckUserInGroup(userId UserID, groupId string) (bool, error)
}

type AuthenticationService interface {
	AccountService
	SessionService
	GroupService
	TokenService
}
