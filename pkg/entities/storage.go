package entities

type AccountStore interface {
	// Create
	SaveUser(user *Account) error
	// Read
	GetUserByUserID(email string) (*Account, error)
	GetUserByEmail(email string) (*Account, error)
	GetUserByUsername(username string) (*Account, error)
	// Update
	UpdateUserByID(user *Account) error
}

type SessionStore interface {
	// Create
	SaveSession(session *Session) error
	// Read
	GetSessionByID(sessionID string) (*Session, error)
	GetUserBySessionID(sessionID string) (*Account, error)
	// Update
	InvalidateSessionByID(sessionID string) error
}

type GroupStore interface {
	// Create
	SaveGroup(group *UserGroup) error
	SaveGroupAssociation(association *UserGroupAssociation) error
	// Read
	GetGroupByID(groupID string) (*UserGroup, error)
	GetGroupsByUserID(userID string) ([]*UserGroup, error)
	// Update
	UpdateGroupByID(group *UserGroup) error
	// Delete
	DeleteGroupByID(groupID string) error
	DeleteUserGroupAssociation(userID string, groupID string) error
}

type UserManagementStore interface {
	AccountStore
	SessionStore
	GroupStore
}
