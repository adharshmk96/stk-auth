package handlers

import (
	"time"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk"
)

type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func handleUserError(err error, ctx stk.Context) {
	var status int
	var message string

	switch err {
	case stk.ErrInvalidJSON:
		{
			status = 400
			message = err.Error()
		}
	case entities.ErrParsingUserID:
		{
			status = 400
			message = err.Error()
		}
	case svrerr.ErrNoAccountFound:
		{
			status = 404
			message = err.Error()
		}
	case svrerr.ErrStoringAccount:
		{
			status = 500
			message = err.Error()
		}
	// define default cases here
	case svrerr.ErrHasingPassword:
		fallthrough
	default:
		{
			status = 500
			message = stk.ErrInternalServer.Error()
		}
	}

	ctx.Status(status).JSONResponse(stk.Map{
		"message": message,
	})
}
