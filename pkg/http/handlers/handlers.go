package handlers

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
)

type authenticationHandler struct {
	authService entities.AuthenticationService
}

func NewUserManagementHandler(userService entities.AuthenticationService) entities.AuthenticationHandler {
	return &authenticationHandler{
		authService: userService,
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
