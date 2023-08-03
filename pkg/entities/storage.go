package entities

import "github.com/adharshmk96/stk-auth/pkg/entities/ds"

type userStore interface {
	// Create
	SaveUser(user *ds.Account) error
	// Read
	GetTotalUsersCount() (int64, error)
	GetUserByUserID(email string) (*ds.Account, error)
	GetUserByEmail(email string) (*ds.Account, error)
	GetUserByUsername(username string) (*ds.Account, error)
	GetUserList(limit int, offset int) ([]*ds.Account, error)
	// Update
	UpdateUserByID(user *ds.Account) error
	// Delete
	DeleteUserByID(userID string) error
}

type sessionStore interface {
	// Create
	SaveSession(session *ds.Session) error
	// Read
	GetSessionByID(sessionID string) (*ds.Session, error)
	GetUserBySessionID(sessionID string) (*ds.Account, error)
	// Update
	InvalidateSessionByID(sessionID string) error
}

type groupStore interface {
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
	userStore
	sessionStore
	groupStore
}
