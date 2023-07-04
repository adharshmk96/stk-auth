package entities

import "github.com/adharshmk96/stk/gsk"

type AccountHandler interface {
	RegisterUser(gc gsk.Context)
	LoginUserSession(gc gsk.Context)
	LoginUserToken(gc gsk.Context)
	GetSessionUser(gc gsk.Context)
	GetTokenUser(gc gsk.Context)
	LogoutUser(gc gsk.Context)

	ChangePassword(gc gsk.Context)
}
