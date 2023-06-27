package handlers

import (
	"net/http"
	"time"

	"github.com/adharshmk96/stk"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/http/validator"
	"github.com/adharshmk96/stk-auth/pkg/infra/config"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
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

// Session based login,
// NOTE: session id should not be exposed to client, it should be in httpOnly cookie
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

	secureCookie := config.SERVER_MODE == config.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     config.SESSION_COOKIE_NAME,
		Value:    sessionData.SessionID,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
	}

	response := stk.Map{
		"message": transport.SUCCESS_LOGIN,
	}

	ctx.SetCookie(cookie)
	ctx.Status(http.StatusOK).JSONResponse(response)
}

// Session + Token based login,
// NOTE: session token should not be exposed to client, it should be in httpOnly cookie
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

	secureCookie := config.SERVER_MODE == config.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     config.JWT_SESSION_COOKIE_NAME,
		Value:    jwtToken,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
	}

	response := stk.Map{
		"message": transport.SUCCESS_LOGIN,
	}

	ctx.SetCookie(cookie)
	ctx.Status(http.StatusOK).JSONResponse(response)
}

func (h *accountHandler) GetSessionUser(ctx stk.Context) {
	sessionCookie, err := ctx.GetCookie(config.SESSION_COOKIE_NAME)
	if err != nil {
		ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	if sessionCookie == nil || sessionCookie.Value == "" {
		ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	user, err := h.userService.GetUserBySessionId(sessionCookie.Value)
	if err != nil {
		if err == svrerr.ErrInvalidSession {
			ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
				"message": transport.ERROR_UNAUTHORIZED,
			})
		} else {
			ctx.Status(http.StatusInternalServerError).JSONResponse(stk.Map{
				"message": transport.INTERNAL_SERVER_ERROR,
			})
		}
		return
	}

	response := transport.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	ctx.Status(http.StatusOK).JSONResponse(response)
}

func (h *accountHandler) GetSessionTokenUser(ctx stk.Context) {
	sessionCookie, err := ctx.GetCookie(config.JWT_SESSION_COOKIE_NAME)
	if err != nil {
		ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	if sessionCookie == nil || sessionCookie.Value == "" {
		ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	userWithToken, err := h.userService.GetUserBySessionToken(sessionCookie.Value)
	if err != nil {
		if err == svrerr.ErrInvalidToken {
			ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
				"message": transport.ERROR_UNAUTHORIZED,
			})
		} else if err == svrerr.ErrInvalidSession {
			ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
				"message": transport.ERROR_UNAUTHORIZED,
			})
		} else {
			ctx.Status(http.StatusInternalServerError).JSONResponse(stk.Map{
				"message": transport.INTERNAL_SERVER_ERROR,
			})
		}
		return
	}

	response := transport.UserResponse{
		ID:        userWithToken.ID.String(),
		Username:  userWithToken.Username,
		Email:     userWithToken.Email,
		CreatedAt: userWithToken.CreatedAt,
		UpdatedAt: userWithToken.UpdatedAt,
	}
	secureCookie := config.SERVER_MODE == config.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     config.JWT_SESSION_COOKIE_NAME,
		Value:    userWithToken.Token,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
	}

	ctx.SetCookie(cookie)

	ctx.Status(http.StatusOK).JSONResponse(response)
}

func (h *accountHandler) LogoutUser(ctx stk.Context) {
	sessionCookie, sessionToken, err := transport.GetSessionOrTokenFromCookie(ctx)
	if err != nil {
		ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	var cookieName string
	if sessionCookie != nil && sessionCookie.Value != "" {
		err := h.userService.LogoutUserBySessionId(sessionCookie.Value)
		if err != nil {
			transport.HandleLogoutError(err, ctx)
			return
		}
		cookieName = config.SESSION_COOKIE_NAME
	} else {
		err := h.userService.LogoutUserBySessionToken(sessionToken.Value)
		if err != nil {
			transport.HandleLogoutError(err, ctx)
			return
		}
		cookieName = config.JWT_SESSION_COOKIE_NAME
	}

	secureCookie := config.SERVER_MODE == config.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 0, -1),
	}

	ctx.SetCookie(cookie)

	ctx.Status(http.StatusOK).JSONResponse(stk.Map{
		"message": transport.SUCCESS_LOGOUT,
	})
}
