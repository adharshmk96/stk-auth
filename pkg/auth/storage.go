package auth

type AccountStore interface {
	// Create
	SaveUser(user *User) error
	// Read
	GetTotalUsersCount() (int64, error)
	GetUserByUserID(email string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByUsername(username string) (*User, error)
	GetUserList(limit int, offset int) ([]*User, error)
	// Update
	UpdateUserByID(user *User) error
	// Delete
	DeleteUserByID(userID string) error
}

type SessionStore interface {
	// Create
	SaveSession(session *Session) error
	// Read
	GetSessionByID(sessionID string) (*Session, error)
	GetUserBySessionID(sessionID string) (*User, error)
	// Update
	InvalidateSessionByID(sessionID string) error
}

type GroupStore interface {
	// Create
	SaveGroup(group *Group) error
	SaveGroupAssociation(association *AccountGroupAssociation) error
	// Read
	GetGroupByID(groupID string) (*Group, error)
	GetGroupsByUserID(userID string) ([]*Group, error)
	CheckUserGroupAssociation(userID string, groupID string) (bool, error)
	// Update
	UpdateGroup(group *Group) error
	// Delete
	DeleteGroupByID(groupID string) error
	DeleteUserGroupAssociation(userID string, groupID string) error
}

type AuthenticationStore interface {
	AccountStore
	SessionStore
	GroupStore
}
