package services_test

import (
	"os"
	"testing"
	"time"

	"github.com/adharshmk96/auth-server/mocks"
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/services"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk/utils"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewUserService(t *testing.T) {
	t.Run("returns a new UserService instance", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)
		assert.NotNil(t, service)
	})
}

func TestAccountService_RegisterUser(t *testing.T) {

	user_password := "testpassword"

	userData := &entities.Account{
		Username: "testuser",
		Password: user_password,
		Email:    "mail@email.com",
	}

	t.Run("returns user with userid if data is valid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(nil)

		// Test successful registration
		user, err := service.RegisterUser(userData)
		assert.NoError(t, err)
		assert.Equal(t, userData, user)

		assert.NotEmpty(t, user.ID)
		// Test salt is generated
		assert.NotEmpty(t, user.Salt)
		// Test password is hashed
		assert.NotEqual(t, user_password, userData.Password)
		// Test timestamps are generated
		assert.NotEmpty(t, user.CreatedAt)
		assert.NotEmpty(t, user.UpdatedAt)
	})

	t.Run("returns error if storage failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrStoringData)

		// Test invalid registration
		user, err := service.RegisterUser(userData)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrStoringData.Error())
		assert.Nil(t, user)
	})

	t.Run("returns error if user exists", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrDuplicateEntry)

		// Test invalid registration
		user, err := service.RegisterUser(userData)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDuplicateEntry.Error())
		assert.Nil(t, user)
	})

}

func TestAccountService_LoginSessionUser(t *testing.T) {

	user_id := entities.UserID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	user_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	salt, _ := utils.GenerateSalt()
	hashedPassword, hashedSalt := utils.HashPassword(user_password, salt)

	storedData := &entities.Account{
		ID:        user_id,
		Username:  "testuser",
		Password:  hashedPassword,
		Email:     user_email,
		Salt:      hashedSalt,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns session with userid if username and password are valid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByUsername", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(nil)

		requestData := &entities.Account{
			Username: user_name,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByEmail", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, userSession.UserID)
		assert.NotEmpty(t, userSession.SessionID)
		assert.NotEmpty(t, userSession.CreatedAt)
		assert.NotEmpty(t, userSession.UpdatedAt)
		assert.True(t, userSession.Valid)
	})

	t.Run("returns session with userid if email and password are valid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(nil)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, userSession.UserID)
		assert.NotEmpty(t, userSession.SessionID)
		assert.NotEmpty(t, userSession.CreatedAt)
		assert.NotEmpty(t, userSession.UpdatedAt)
		assert.True(t, userSession.Valid)
	})

	t.Run("returns error if password is incorrect", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		requestData := &entities.Account{
			Email:    user_email,
			Password: "wrongpassword",
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.EqualError(t, err, svrerr.ErrInvalidCredentials.Error())
		assert.Nil(t, userSession)
	})

	t.Run("returns retrieve data error if account retrieving failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(nil, svrerr.ErrRetrievingData)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrRetrievingData.Error())
		assert.Nil(t, userSession)
	})

	t.Run("returns error if session store failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(svrerr.ErrRetrievingData)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertCalled(t, "SaveSession", mock.Anything)

		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrRetrievingData.Error())
		assert.Nil(t, userSession)
	})

	t.Run("returns invalid credential error if user does not exist", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(nil, svrerr.ErrEntryNotFound)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.EqualError(t, err, svrerr.ErrInvalidCredentials.Error())
		assert.Nil(t, userSession)
	})

}

func setupKeys() (string, string) {
	var privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC8p0Wv/07CoOip
XxtZHmHCyz+hV1gJqnOhyhmc68XQynXDI96O65PKUCjYxtncAg3KSZExYvX6obyv
FsnluNmHffy+QBVQReGHZ2yTzqpionwuJ4ZYLNMGbiDk2td9x8DGdSX2fFZF1qnJ
0ulSph44anzF0Uqx6B5fi9M6IkD622/6GfMGEmE/1ssObECm66DOLzLIYOB5EHj9
RkUTaoCs88Q9/uFejKk1Y0QOObnPx+MKJ9I36vplxl2fKRfHATvpqSt/UYsElDu5
zKEi1Olewe8ozv4C/8cmIlJ6b2N3M89izRo0ZUCY/TGp46O5gAsNK+IQnHSk7kDb
Del3WsSpAgMBAAECggEAY3mcUGJCKHRqWizRIdvYVruPcMa6oFYlpNEJUmosI50u
HViDmT707f/4md24sL7QgLLsAWuaIq836+cLTLt80GoJZFQsKOjANALACOw3gc0F
x9yFhWcVWtWlOKeAa01yA/Nvshn779VyL/6rky4Oz1avNivWxBqOMXlsRsIbG2rC
mCRJFH99sO0KYAt5BgSQkI/ygunniwRH+VOhn+qzDDFhBQXjfTAW0CbRJPrXLeCs
WR0Mjo48IL++vlNGLqHhKNd85HtEv5G5QTP/I9DVCCOReoYvpsNscf332kCAkbv5
xtxKd+voKRFrTHMivJ5+Q1GVb34zcz7xJ9cVHwVNgQKBgQD4G1GMxfV9aryvtsRL
oybQG8kn03ok/lC0R7qyydDcTi8qCR7ITz0Q7iwy/cY+vE17lkmQNZr4zuLEbWJl
rhWWji8ZttcKilYcxGoycuAygTPjeaFL7joxfI2RPrPgmZUnG58KK/YbkYA8TYbO
Tn2eb0VTfV5kKVt8Z5gVcacZ2QKBgQDCp73sO+po/TJDIWLF1izhEzub44a+K1BZ
9GP/fEqCcS5lKXPt3Ob6dI4b6ybUF+MUBG7whBiAAgZ1AW5bvCgLmRAEjXUXoArd
rejmmG2bgBVCnULK3m0BSJO2IIUjLntkJ6LNvJpCRsNtsrjzjkcJ3IlsvBBA4E4Z
ZLG64OrvUQKBgDE9wsast1dH6uD45iaY3+gny5mi6DgVXVEad1xqn5BJ2CSAoOJi
j50fmBgas9DZsIsZvcnoSbSd4vXXO9MwZMp3t7NjzXQjFoopFWaj1AlSCUlZZ4DZ
bCVMMhCkoDCwaqDTY5IyPWslSo0tWdbyTw41yU2TsTsx1h1vtghzgRWpAoGATi+6
Za0bVth82+IJHpYMqMtk4hTeBny3Zap4kCKIeySjEhc4bY6RaIBwpF4r1n1RxLST
KyCkBqbJmS3d+hL1stLkUC/RnI+4TZqRNi57uD4WTA+GyJ3XAvD4A+vEDoGZJn2V
MzZSb9SkoudqysmXVyqyOG7ByI1QUXrUuM+nDkECgYByMK0F7VTpCyrXtKV9v+h8
9qMAUsn6zdHr18CFYzxr8ah8aJkA8bhWRHqOFnaDorcuJ/AeJV9irQ4cj9dhStAO
h3t4BI3tAhV779CvXoTbjwXtWGeAUOCuvTjQgJeZiuGQXaj+rQlgWCzk9HK4sV3G
QR7Naff0gsNlqCJibCwOhA==
-----END PRIVATE KEY-----
`
	var publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvKdFr/9OwqDoqV8bWR5h
wss/oVdYCapzocoZnOvF0Mp1wyPejuuTylAo2MbZ3AINykmRMWL1+qG8rxbJ5bjZ
h338vkAVUEXhh2dsk86qYqJ8LieGWCzTBm4g5NrXfcfAxnUl9nxWRdapydLpUqYe
OGp8xdFKsegeX4vTOiJA+ttv+hnzBhJhP9bLDmxApuugzi8yyGDgeRB4/UZFE2qA
rPPEPf7hXoypNWNEDjm5z8fjCifSN+r6ZcZdnykXxwE76akrf1GLBJQ7ucyhItTp
XsHvKM7+Av/HJiJSem9jdzPPYs0aNGVAmP0xqeOjuYALDSviEJx0pO5A2w3pd1rE
qQIDAQAB
-----END PUBLIC KEY-----
`
	os.MkdirAll(".keys", 0666)
	os.WriteFile(".keys/private_key.pem", []byte(privateKey), 0666)
	os.WriteFile(".keys/public_key.pem", []byte(publicKey), 0666)

	return privateKey, publicKey
}

func tearDown() {
	os.RemoveAll(".keys")
}

func TestAccountService_LoginSessionUserToken(t *testing.T) {

	_, publicKey := setupKeys()
	defer tearDown()

	user_id := entities.UserID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	user_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	salt, _ := utils.GenerateSalt()
	hashedPassword, hashedSalt := utils.HashPassword(user_password, salt)

	storedData := &entities.Account{
		ID:        user_id,
		Username:  "testuser",
		Password:  hashedPassword,
		Email:     user_email,
		Salt:      hashedSalt,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	testJwtClaims := func(userToken string) {
		// check jwt token
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(userToken, claims, func(token *jwt.Token) (interface{}, error) {
			key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
			return key, err
		})

		assert.NoError(t, err)
		assert.True(t, token.Valid)
		assert.NotNil(t, claims["iat"])
		assert.NotNil(t, claims["session_id"])
		assert.Equal(t, claims["user_id"], user_id.String())
		assert.NotNil(t, claims["sub"])
		assert.NotNil(t, claims["exp"])
		assert.NotNil(t, claims["aud"])
	}

	t.Run("returns token with userid if username and password are valid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByUsername", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(nil)

		requestData := &entities.Account{
			Username: user_name,
			Password: user_password,
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByEmail", mock.Anything)

		assert.NoError(t, err)
		assert.NotEmpty(t, userToken)

		testJwtClaims(userToken)

	})

	t.Run("returns token with userid if email and password are valid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(nil)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)

		assert.NoError(t, err)
		assert.NotEmpty(t, userToken)

		testJwtClaims(userToken)
	})

	t.Run("returns error if password is incorrect", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		requestData := &entities.Account{
			Email:    user_email,
			Password: "wrongpassword",
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.EqualError(t, err, svrerr.ErrInvalidCredentials.Error())
		assert.Empty(t, userToken)
	})

	t.Run("returns retrieve data error if account retrieving failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(nil, svrerr.ErrRetrievingData)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrRetrievingData.Error())
		assert.Empty(t, userToken)
	})

	t.Run("returns error if session store failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(svrerr.ErrRetrievingData)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertCalled(t, "SaveSession", mock.Anything)

		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrRetrievingData.Error())
		assert.Empty(t, userSession)
	})

	t.Run("returns invalid credential error if user does not exist", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(nil, svrerr.ErrEntryNotFound)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.EqualError(t, err, svrerr.ErrInvalidCredentials.Error())
		assert.Empty(t, userToken)
	})

}
