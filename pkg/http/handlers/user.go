package handlers

import (
	"net/http"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/http/validator"
	"github.com/adharshmk96/stk/gsk"
)

// RegisterUser registers a new user
// - Decodes and Validates the user information from body
// - Calls the service layer to store the user information
// - Returns the user information
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword,
// - storage: ErrDBStorageFailed, ErrDBDuplicateEntry
func (h *userManagmentHandler) RegisterUser(gc gsk.Context) {
	var user *entities.Account

	err := gc.DecodeJSONBody(&user)
	if err != nil {
		transport.HandleJsonDecodeError(err, gc)
		return
	}

	errorMessages := validator.ValidateRegistration(user)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, gc)
		return
	}

	createdUser, err := h.userService.CreateUser(user)
	if err != nil {
		transport.HandleRegistrationError(err, gc)
		return
	}

	response := transport.UserResponse{
		ID:        createdUser.ID.String(),
		Username:  createdUser.Username,
		Email:     createdUser.Email,
		CreatedAt: createdUser.CreatedAt,
		UpdatedAt: createdUser.UpdatedAt,
	}

	gc.Status(http.StatusCreated).JSONResponse(response)
}

// ChangePassword changes the password of the user
// - Decodes and Validates the user information from body
// - Calls the service layer to change the password
// - Returns the success message
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword, ErrInvalidCredentials, ErrDBEntryNotFound
// - storage: ErrDBStorageFailed
func (h *userManagmentHandler) ChangePassword(gc gsk.Context) {
	var credentials *transport.CredentialUpdate

	err := gc.DecodeJSONBody(&credentials)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_BODY,
		})
		return
	}

	user := credentials.Credentials

	err = h.userService.Authenticate(user)
	if err != nil {
		transport.HandleChangePasswordError(err, gc)
		return
	}

	updatedUser := credentials.NewCredentials

	err = h.userService.ChangePassword(updatedUser)
	if err != nil {
		transport.HandleChangePasswordError(err, gc)
		return
	}

	gc.Status(http.StatusOK).JSONResponse(gsk.Map{
		"message": transport.SUCCESS_CHANGED_PASSWORD,
	})
}
