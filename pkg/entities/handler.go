package entities

import "github.com/adharshmk96/stk/gsk"

type AccountHandler interface {
	RegisterUser(ctx gsk.Context)
	LoginUserSession(ctx gsk.Context)
	LoginUserSessionToken(ctx gsk.Context)
	GetSessionUser(ctx gsk.Context)
	GetSessionTokenUser(ctx gsk.Context)
	LogoutUser(ctx gsk.Context)
	// Token flow
	// LoginUserToken(ctx gsk.Context)
	// ValidateToken(ctx gsk.Context)
	// RefreshToken(ctx gsk.Context)
}
