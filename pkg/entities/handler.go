package entities

import "github.com/adharshmk96/stk/gsk"

type AccountHandler interface {
	RegisterUser(gc gsk.Context)
	ChangePassword(gc gsk.Context)
}

type SessionHandler interface {
	LoginUserSession(gc gsk.Context)
	LoginUserToken(gc gsk.Context)
	LogoutUser(gc gsk.Context)
	GetSessionUser(gc gsk.Context)
	GetTokenUser(gc gsk.Context)
}

type GroupHandler interface {
	// CreateGroup(gc gsk.Context)
	// GetGroup(gc gsk.Context)
	// GetGroups(gc gsk.Context)
	// UpdateGroup(gc gsk.Context)
	// DeleteGroup(gc gsk.Context)
}

type UserManagmentHandler interface {
	AccountHandler
	SessionHandler
	GroupHandler
}
