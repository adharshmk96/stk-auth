package entities

import "github.com/adharshmk96/stk/gsk"

type accountHandler interface {
	RegisterAccount(gc *gsk.Context)
	ChangeCredentials(gc *gsk.Context)
}

type sessionHandler interface {
	LoginAccountSession(gc *gsk.Context)
	LoginAccountToken(gc *gsk.Context)
	LogoutAccount(gc *gsk.Context)
	GetSessionAccount(gc *gsk.Context)
	GetTokenAccount(gc *gsk.Context)
}

type AuthenticationHandler interface {
	accountHandler
	sessionHandler
}

type AdminHandler interface {
	GetAccountList(gc *gsk.Context)
	GetAccountDetails(gc *gsk.Context)

	CreateGroup(gc *gsk.Context)
}

type OauthHandler interface {
	GoogleOauthLogin(gc *gsk.Context)
	GoogleOauthCallback(gc *gsk.Context)
}

type AdministrationHandler interface {
}
