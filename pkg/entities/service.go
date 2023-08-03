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
	CreateUser(user *ds.User) (*ds.User, error)
	Authenticate(login *ds.User) error
	ChangePassword(user *ds.User) error
	GetUserByID(userId string) (*ds.User, error)

	// Admin methods
	GetUserList(limit int, offset int) ([]*ds.User, error)
	GetTotalUsersCount() (int64, error)
	GetUserDetails(userId ds.UserID) (*ds.User, error)
}

type sessionService interface {
	CreateSession(user *ds.User) (*ds.Session, error)
	GetUserBySessionId(sessionId string) (*ds.User, error)
	LogoutUserBySessionId(sessionId string) error
}

type groupService interface {
	CreateGroup(group *ds.Group) (*ds.Group, error)
	GetGroupsByUserID(userId ds.UserID) ([]*ds.Group, error)
	UpdateGroupByID(group *ds.Group) error
	DeleteGroupByID(groupId string) error
	AddUserToGroup(userId ds.UserID, groupId string) error
	RemoveUserFromGroup(userId ds.UserID, groupId string) error
	CheckUserInGroup(userId ds.UserID, groupId string) (bool, error)
}

type AuthenticationService interface {
	userService
	sessionService
	groupService
	tokenService
}
