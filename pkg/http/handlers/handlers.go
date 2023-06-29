package handlers

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
)

type accountHandler struct {
	userService entities.AccountService
}

func NewAccountHandler(userService entities.AccountService) entities.AccountHandler {
	return &accountHandler{
		userService: userService,
	}
}
