package handlers

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
)

type accountHandler struct {
	userService entities.UserManagementService
}

func NewUserManagementHandler(userService entities.UserManagementService) entities.UserManagmentHandler {
	return &accountHandler{
		userService: userService,
	}
}
