package handlers

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
)

type accountHandler struct {
	authService entities.AuthenticationService
}

func NewAccountHandler(authService entities.AuthenticationService) entities.AuthenticationHandler {
	return &accountHandler{
		authService: authService,
	}
}

type adminHandler struct {
	authService entities.AuthenticationService
}

func NewAdminHandler(authService entities.AuthenticationService) entities.AdminHandler {
	return &adminHandler{
		authService: authService,
	}
}
