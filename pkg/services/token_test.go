package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestAccountService_TestGenerateJWT(t *testing.T) {

	t.Run("generates a valid token", func(t *testing.T) {
		_, _ = setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(dbStorage)

		userId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID: userId,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
				Subject:   viper.GetString(constants.ENV_JWT_SUBJECT),
			},
		}

		token, err := service.GenerateJWT(claims)
		assert.NoError(t, err)

		parsedClaims, _ := parseToken(token)
		assert.NoError(t, err)

		assert.Equal(t, userId, parsedClaims.UserID)
	})

	t.Run("returns error if key is invalid", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, "")
		viper.AutomaticEnv()

		dbStorage := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(dbStorage)

		userId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID: userId,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
				Subject:   viper.GetString(constants.ENV_JWT_SUBJECT),
			},
		}

		token, err := service.GenerateJWT(claims)
		assert.Error(t, err)

		assert.Empty(t, token)

	})
}

func TestAccountService_ValidateJWT(t *testing.T) {

	t.Run("returns no error if token is valid", func(t *testing.T) {
		_, _ = setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(dbStorage)

		userId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID: userId,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
				Subject:   viper.GetString(constants.ENV_JWT_SUBJECT),
			},
		}

		token, err := service.GenerateJWT(claims)
		assert.NoError(t, err)

		validatedClaims, err := service.ValidateJWT(token)
		assert.NoError(t, err)

		assert.Equal(t, userId, validatedClaims.UserID)
	})

	t.Run("returns error if token is invalid", func(t *testing.T) {
		_, _ = setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(dbStorage)

		userId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID: userId,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
				Subject:   viper.GetString(constants.ENV_JWT_SUBJECT),
			},
		}

		token, err := service.GenerateJWT(claims)
		assert.NoError(t, err)

		invalidToken := token + "invalid"

		_, err = service.ValidateJWT(invalidToken)
		assert.Error(t, err)

	})

}
