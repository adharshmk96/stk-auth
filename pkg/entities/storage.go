package entities

import "github.com/adharshmk96/stk-auth/pkg/entities/ds"

type AccountStore interface {
	// Create
	SaveUser(user *ds.User) error
	// Read
	GetTotalUsersCount() (int64, error)
	GetUserByUserID(email string) (*ds.User, error)
	GetUserByEmail(email string) (*ds.User, error)
	GetUserByUsername(username string) (*ds.User, error)
	GetUserList(limit int, offset int) ([]*ds.User, error)
	// Update
	UpdateUserByID(user *ds.User) error
	// Delete
	DeleteUserByID(userID string) error
}

type SessionStore interface {
	// Create
	SaveSession(session *ds.Session) error
	// Read
	GetSessionByID(sessionID string) (*ds.Session, error)
	GetUserBySessionID(sessionID string) (*ds.User, error)
	// Update
	InvalidateSessionByID(sessionID string) error
}

type GroupStore interface {
	// Create
	SaveGroup(group *ds.Group) error
	SaveGroupAssociation(association *ds.UserGroupAssociation) error
	// Read
	GetGroupByID(groupID string) (*ds.Group, error)
	GetGroupsByUserID(userID string) ([]*ds.Group, error)
	CheckUserGroupAssociation(userID string, groupID string) (bool, error)
	// Update
	UpdateGroup(group *ds.Group) error
	// Delete
	DeleteGroupByID(groupID string) error
	DeleteUserGroupAssociation(userID string, groupID string) error
}

type AuthenticationStore interface {
	AccountStore
	SessionStore
	GroupStore
}
