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
type UserService interface {
	CreateUser(user *User) (*User, error)
	Authenticate(login *User) error
	ChangePassword(user *User) error
	GetUserByID(userId string) (*User, error)
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

// TODO: Split to admin and user
type AuthenticationService interface {
	UserService
	SessionService
	GroupService
	TokenService
}

type AdminService interface {
	GetUserList(limit int, offset int) ([]*User, error)
	GetTotalUsersCount() (int64, error)
	GetUserDetails(userId UserID) (*User, error)
	// UpdateUser(user *Account) error
	// DeleteUser(userId string) error
}
