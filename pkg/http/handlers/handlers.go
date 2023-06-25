package handlers

import (
	"github.com/adharshmk96/auth-server/pkg/services"
	"github.com/adharshmk96/stk"
)

type accountHandler struct {
	userService services.AccountService
}

type AccountHandler interface {
	RegisterUser(ctx stk.Context)
	LoginUserSession(ctx stk.Context)
}

func NewAccountHandler(userService services.AccountService) AccountHandler {
	return &accountHandler{
		userService: userService,
	}
}
