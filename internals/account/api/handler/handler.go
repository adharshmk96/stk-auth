package handler

import (
	"github.com/adharshmk96/stk-auth/internals/account/domain"
)

type accountHandler struct {
	service domain.AccountService
}

func NewAccountHandler(service domain.AccountService) domain.AccountHandlers {
	return &accountHandler{
		service: service,
	}
}
