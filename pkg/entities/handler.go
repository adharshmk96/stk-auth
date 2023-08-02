package entities

import "github.com/adharshmk96/stk/gsk"

type userHandler interface {
	RegisterUser(gc *gsk.Context)
	ChangeCredentials(gc *gsk.Context)
}

type sessionHandler interface {
	LoginUserSession(gc *gsk.Context)
	LoginUserToken(gc *gsk.Context)
	LogoutUser(gc *gsk.Context)
	GetSessionUser(gc *gsk.Context)
	GetTokenUser(gc *gsk.Context)
}

type AuthenticationHandler interface {
	userHandler
	sessionHandler
}

type AdminHandler interface {
	GetUserList(gc *gsk.Context)
	GetUserDetails(gc *gsk.Context)

	//CreateGroup(gc *gsk.Context)
}
