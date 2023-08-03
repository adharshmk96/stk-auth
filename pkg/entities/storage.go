package entities

import "github.com/adharshmk96/stk-auth/pkg/entities/ds"

type accountStore interface {
	// Create
	SaveAccount(account *ds.Account) error
	// Read
	GetTotalAccountsCount() (int64, error)
	GetAccountByAccountID(email string) (*ds.Account, error)
	GetAccountByEmail(email string) (*ds.Account, error)
	GetAccountByUsername(username string) (*ds.Account, error)
	GetAccountList(limit int, offset int) ([]*ds.Account, error)
	// Update
	UpdateAccountByID(account *ds.Account) error
	// Delete
	DeleteAccountByID(accountID string) error
}

type sessionStore interface {
	// Create
	SaveSession(session *ds.Session) error
	// Read
	GetSessionByID(sessionID string) (*ds.Session, error)
	GetAccountBySessionID(sessionID string) (*ds.Account, error)
	// Update
	InvalidateSessionByID(sessionID string) error
}

type groupStore interface {
	// Create
	SaveGroup(group *ds.Group) error
	SaveGroupAssociation(association *ds.AccountGroupAssociation) error
	// Read
	GetGroupByID(groupID string) (*ds.Group, error)
	GetGroupsByAccountID(accountID string) ([]*ds.Group, error)
	CheckAccountGroupAssociation(accountID string, groupID string) (bool, error)
	// Update
	UpdateGroup(group *ds.Group) error
	// Delete
	DeleteGroupByID(groupID string) error
	DeleteAccountGroupAssociation(accountID string, groupID string) error
}

type AuthenticationStore interface {
	accountStore
	sessionStore
	groupStore
}
