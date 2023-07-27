package auth

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
	CreateUser(user *User) (*User, error)
	Authenticate(login *User) error
	ChangePassword(user *User) error
	GetUserByID(userId string) (*User, error)

	// For Admin
	GetUserList(limit int, offset int) ([]*User, error)
	GetTotalUsersCount() (int64, error)
	// UpdateUser(user *Account) error
	// DeleteUser(userId string) error
}

type SessionService interface {
	CreateSession(user *User) (*Session, error)
	GetUserBySessionId(sessionId string) (*User, error)
	LogoutUserBySessionId(sessionId string) error
}

type GroupService interface {
	CreateGroup(group *Group) (*Group, error)
	GetGroupsByUserID(userId UserID) ([]*Group, error)
	UpdateGroupByID(group *Group) error
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
