package handlers

import (
	"net/http"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/http/transport"
	"github.com/adharshmk96/auth-server/pkg/http/validator"
	"github.com/adharshmk96/auth-server/pkg/infra/config"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk"
)

func (h *accountHandler) RegisterUser(ctx stk.Context) {
	var user *entities.Account

	err := ctx.DecodeJSONBody(&user)
	if err != nil {
		transport.HandleUserError(err, ctx)
		return
	}

	errorMessages := validator.ValidateUser(user)
	if len(errorMessages) > 0 {
		ctx.Status(400).JSONResponse(stk.Map{
			"error":   svrerr.ErrInvalidData.Error(),
			"details": errorMessages,
		})
		return
	}

	createdUser, err := h.userService.RegisterUser(user)
	if err != nil {
		transport.HandleUserError(err, ctx)
		return
	}

	response := transport.UserResponse{
		ID:        createdUser.ID.String(),
		Username:  createdUser.Username,
		Email:     createdUser.Email,
		CreatedAt: createdUser.CreatedAt,
		UpdatedAt: createdUser.UpdatedAt,
	}

	ctx.Status(201).JSONResponse(response)
}

func (h *accountHandler) LoginUserSession(ctx stk.Context) {
	var userLogin *entities.Account

	err := ctx.DecodeJSONBody(&userLogin)
	if err != nil {
		transport.HandleUserError(err, ctx)
		return
	}

	errorMessages := validator.ValidateLogin(userLogin)
	if len(errorMessages) > 0 {
		ctx.Status(400).JSONResponse(stk.Map{
			"error":   svrerr.ErrInvalidData.Error(),
			"details": errorMessages,
		})
		return
	}

	jwtToken, err := h.userService.LoginUserSession(userLogin)
	if err != nil {
		transport.HandleUserError(err, ctx)
		return
	}

	httpOnly := config.SERVER_MODE == config.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     config.SESSION_COOKIE_NAME,
		Value:    jwtToken,
		HttpOnly: httpOnly,
		Path:     "/",
	}

	ctx.SetCookie(cookie)
	ctx.Status(200).JSONResponse(stk.Map{
		"message": "login successful",
	})
}
