package auth

import "github.com/adharshmk96/stk/gsk"

type PublicUserHandler interface {
	RegisterUser(gc *gsk.Context)
	ChangeCredentials(gc *gsk.Context)
}

type PublicSessionHandler interface {
	LoginUserSession(gc *gsk.Context)
	LoginUserToken(gc *gsk.Context)
	LogoutUser(gc *gsk.Context)
	GetSessionUser(gc *gsk.Context)
	GetTokenUser(gc *gsk.Context)
}

type PublicGroupHandler interface {
	CreateGroup(gc *gsk.Context)
	// GetGroup(gc *gsk.Context)
	// GetGroups(gc *gsk.Context)
	// UpdateGroup(gc *gsk.Context)
	// DeleteGroup(gc *gsk.Context)
}

type AuthenticationHandler interface {
	PublicUserHandler
	PublicSessionHandler
}

type AdministrationHandler interface {
	// Admin APIs
	GetUserList(gc *gsk.Context)
	PublicGroupHandler
}
