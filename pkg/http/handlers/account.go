package handlers

import (
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/services"
	"github.com/adharshmk96/stk"
)

type accountHandler struct {
	userService entities.AccountService
}

type AccountHandler interface {
	RegisterUser(ctx stk.Context)
	GetUserByID(ctx stk.Context)
}

func NewAccountHandler(userService entities.AccountService) AccountHandler {
	return &accountHandler{
		userService: userService,
	}
}

func handleRegisterUserError(err error, ctx stk.Context) {
	switch err {
	case stk.ErrInvalidJSON:
		{
			ctx.Status(400).JSONResponse(stk.Map{
				"message": err.Error(),
			})
		}
	case services.ErrStoringAccount:
		{
			ctx.Status(500).JSONResponse(stk.Map{
				"message": err.Error(),
			})
		}
	// define default cases here
	case services.ErrHasingPassword:
		fallthrough
	default:
		{
			ctx.Status(500).JSONResponse(stk.Map{
				"message": stk.ErrInternalServer.Error(),
			})
		}
	}
}

func (h *accountHandler) RegisterUser(ctx stk.Context) {
	var user *entities.Account

	err := ctx.DecodeJSONBody(&user)
	if err != nil {
		handleRegisterUserError(err, ctx)
		return
	}

	createdUser, err := h.userService.RegisterUser(user)
	if err != nil {
		handleRegisterUserError(err, ctx)
		return
	}

	response := RegisterResponse{
		ID:        createdUser.ID.String(),
		Username:  createdUser.Username,
		Email:     createdUser.Email,
		CreatedAt: createdUser.CreatedAt,
		UpdatedAt: createdUser.UpdatedAt,
	}

	ctx.Status(200).JSONResponse(response)
}

func (h *accountHandler) GetUserByID(ctx stk.Context) {

	id := ctx.GetParam("id")

	ctx.Status(200).JSONResponse(stk.Map{
		"message": "user id " + id,
	})
}
