package handler_test

import (
	"net/http"
	"testing"

	"github.com/adharshmk96/stk-auth/internals/account/api/handler"
	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk/gsk"
	"github.com/stretchr/testify/assert"
)

func TestAccountDetails(t *testing.T) {
	t.Run("AccountDetails returns unauthorized", func(t *testing.T) {
		// Arrange
		service := mocks.NewAccountService(t)
		accountHandler := handler.NewAccountHandler(service)
		server := gsk.New()
		server.Get("/account", accountHandler.AccountDetails)

		// Act
		rw, err := server.Test("GET", "/account", nil)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, 401, rw.Code)

	})

}

func TestLogout(t *testing.T) {
	t.Run("Logout returns unauthorized", func(t *testing.T) {
		// Arrange
		service := mocks.NewAccountService(t)

		accountHandler := handler.NewAccountHandler(service)
		server := gsk.New()
		server.Get("/logout", accountHandler.Logout)

		// Act
		rw, err := server.Test("GET", "/logout", nil)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, 401, rw.Code)
	})

	t.Run("Logout returns success", func(t *testing.T) {
		// Arrange
		service := mocks.NewAccountService(t)
		service.On("EndSession", "session").Return(nil)
		accountHandler := handler.NewAccountHandler(service)
		server := gsk.New()
		server.Get("/logout", accountHandler.Logout)

		// Act
		testParams := gsk.TestParams{
			Cookies: []*http.Cookie{
				{
					Name:  "session",
					Value: "session",
				},
			},
		}
		rw, err := server.Test("GET", "/logout", nil, testParams)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, 200, rw.Code)

		cookies := rw.Result().Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, "session", cookies[0].Name)
		assert.Equal(t, "", cookies[0].Value)
		assert.Equal(t, "/", cookies[0].Path)
		assert.Equal(t, true, cookies[0].HttpOnly)
	})
}
