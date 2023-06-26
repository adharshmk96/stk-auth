package handlers

import (
	"github.com/adharshmk96/stk"
	"github.com/adharshmk96/stk-auth/pkg/services"
)

type accountHandler struct {
	userService services.AccountService
}

type AccountHandler interface {
	RegisterUser(ctx stk.Context)
	LoginUserSession(ctx stk.Context)
	LoginUserSessionToken(ctx stk.Context)
	GetSessionUser(ctx stk.Context)
	GetSessionTokenUser(ctx stk.Context)
}

func NewAccountHandler(userService services.AccountService) AccountHandler {
	return &accountHandler{
		userService: userService,
	}
}
