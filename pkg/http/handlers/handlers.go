package handlers

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
)

type authenticationHandler struct {
	userService entities.AuthenticationService
}

func NewUserManagementHandler(userService entities.AuthenticationService) entities.AuthenticationHandler {
	return &authenticationHandler{
		userService: userService,
	}
}
