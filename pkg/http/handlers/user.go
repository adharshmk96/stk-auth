package handlers

import (
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/stk"
)

type userHandler struct {
	userService entities.UserService
}

type UserHandler interface {
	RegisterUser(ctx stk.Context)
	GetUserByID(ctx stk.Context)
}

func NewUserHandler(userService entities.UserService) UserHandler {
	return &userHandler{
		userService: userService,
	}
}

func (h *userHandler) RegisterUser(ctx stk.Context) {
	var user *entities.User

	ctx.DecodeJSONBody(&user)

	createdUser, err := h.userService.RegisterUser(user)

	if err != nil {
		ctx.Status(500).JSONResponse(stk.Map{
			"message": err.Error(),
		})
		return
	}

	ctx.Status(200).JSONResponse(createdUser)
}

func (h *userHandler) GetUserByID(ctx stk.Context) {

	id := ctx.GetParam("id")

	ctx.Status(200).JSONResponse(stk.Map{
		"message": "user id " + id,
	})
}
