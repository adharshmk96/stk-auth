package handlers

import (
	"net/http"

	"github.com/adharshmk96/stk"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/http/validator"
	"github.com/adharshmk96/stk-auth/pkg/infra/config"
)

func (h *accountHandler) RegisterUser(ctx stk.Context) {
	var user *entities.Account

	err := ctx.DecodeJSONBody(&user)
	if err != nil {
		transport.HandleJsonDecodeError(err, ctx)
		return
	}

	errorMessages := validator.ValidateRegistration(user)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, ctx)
		return
	}

	createdUser, err := h.userService.RegisterUser(user)
	if err != nil {
		transport.HandleRegistrationError(err, ctx)
		return
	}

	response := transport.UserResponse{
		ID:        createdUser.ID.String(),
		Username:  createdUser.Username,
		Email:     createdUser.Email,
		CreatedAt: createdUser.CreatedAt,
		UpdatedAt: createdUser.UpdatedAt,
	}

	ctx.Status(http.StatusCreated).JSONResponse(response)
}

func (h *accountHandler) LoginUserSession(ctx stk.Context) {
	var userLogin *entities.Account

	err := ctx.DecodeJSONBody(&userLogin)
	if err != nil {
		transport.HandleJsonDecodeError(err, ctx)
		return
	}

	errorMessages := validator.ValidateLogin(userLogin)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, ctx)
		return
	}

	sessionData, err := h.userService.LoginUserSession(userLogin)
	if err != nil {
		transport.HandleLoginError(err, ctx)
		return
	}

	httpOnly := config.SERVER_MODE == config.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     config.SESSION_COOKIE_NAME,
		Value:    sessionData.SessionID,
		HttpOnly: httpOnly,
		Path:     "/",
	}

	response := stk.Map{
		"message": transport.SUCCESS_LOGIN,
	}

	ctx.SetCookie(cookie)
	ctx.Status(http.StatusOK).JSONResponse(response)
}

func (h *accountHandler) LoginUserSessionToken(ctx stk.Context) {
	var userLogin *entities.Account

	err := ctx.DecodeJSONBody(&userLogin)
	if err != nil {
		transport.HandleJsonDecodeError(err, ctx)
		return
	}

	errorMessages := validator.ValidateLogin(userLogin)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, ctx)
		return
	}

	jwtToken, err := h.userService.LoginUserSessionToken(userLogin)
	if err != nil {
		transport.HandleLoginError(err, ctx)
		return
	}

	httpOnly := config.SERVER_MODE == config.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     config.SESSION_COOKIE_NAME,
		Value:    jwtToken,
		HttpOnly: httpOnly,
		Path:     "/",
	}

	response := stk.Map{
		"message": transport.SUCCESS_LOGIN,
	}

	ctx.SetCookie(cookie)
	ctx.Status(http.StatusOK).JSONResponse(response)
}
