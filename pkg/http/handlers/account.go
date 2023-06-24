package handlers

import (
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
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

func (h *accountHandler) RegisterUser(ctx stk.Context) {
	var user *entities.Account

	err := ctx.DecodeJSONBody(&user)
	if err != nil {
		handleUserError(err, ctx)
		return
	}

	errorMessages := entities.ValidateUser(user)
	if len(errorMessages) > 0 {
		ctx.Status(400).JSONResponse(stk.Map{
			"error":   svrerr.ErrInvalidData.Error(),
			"details": errorMessages,
		})
		return
	}

	createdUser, err := h.userService.RegisterUser(user)
	if err != nil {
		handleUserError(err, ctx)
		return
	}

	response := UserResponse{
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
	userId, err := entities.ParseUserId(id)
	if err != nil {
		handleUserError(err, ctx)
		return
	}

	retrievedUser, err := h.userService.GetUserByID(userId)
	if err != nil {
		handleUserError(err, ctx)
		return
	}

	response := UserResponse{
		ID:        retrievedUser.ID.String(),
		Username:  retrievedUser.Username,
		Email:     retrievedUser.Email,
		CreatedAt: retrievedUser.CreatedAt,
		UpdatedAt: retrievedUser.UpdatedAt,
	}

	ctx.Status(200).JSONResponse(response)
}
