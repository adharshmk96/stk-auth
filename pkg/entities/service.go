package entities

import (
	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

type tokenService interface {
	GenerateJWT(claims *CustomClaims) (string, error)
	ValidateJWT(token string) (*CustomClaims, error)
}
type userService interface {
	CreateUser(user *ds.Account) (*ds.Account, error)
	Authenticate(login *ds.Account) error
	ChangePassword(user *ds.Account) error
	GetUserByID(userId string) (*ds.Account, error)

	// Admin methods
	GetUserList(limit int, offset int) ([]*ds.Account, error)
	GetTotalUsersCount() (int64, error)
	GetUserDetails(userId ds.AccountID) (*ds.Account, error)
}

type sessionService interface {
	CreateSession(user *ds.Account) (*ds.Session, error)
	GetUserBySessionId(sessionId string) (*ds.Account, error)
	LogoutUserBySessionId(sessionId string) error
}

type groupService interface {
	CreateGroup(group *ds.Group) (*ds.Group, error)
	GetGroupsByUserID(userId ds.AccountID) ([]*ds.Group, error)
	UpdateGroupByID(group *ds.Group) error
	DeleteGroupByID(groupId string) error
	AddUserToGroup(userId ds.AccountID, groupId string) error
	RemoveUserFromGroup(userId ds.AccountID, groupId string) error
	CheckUserInGroup(userId ds.AccountID, groupId string) (bool, error)
}

type AuthenticationService interface {
	userService
	sessionService
	groupService
	tokenService
}
