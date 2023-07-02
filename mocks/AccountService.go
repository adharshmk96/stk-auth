// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	entities "github.com/adharshmk96/stk-auth/pkg/entities"
	mock "github.com/stretchr/testify/mock"
)

// AccountService is an autogenerated mock type for the AccountService type
type AccountService struct {
	mock.Mock
}

// GenerateJWT provides a mock function with given fields: user, session
func (_m *AccountService) GenerateJWT(user *entities.Account, session *entities.Session) (string, error) {
	ret := _m.Called(user, session)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(*entities.Account, *entities.Session) (string, error)); ok {
		return rf(user, session)
	}
	if rf, ok := ret.Get(0).(func(*entities.Account, *entities.Session) string); ok {
		r0 = rf(user, session)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(*entities.Account, *entities.Session) error); ok {
		r1 = rf(user, session)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserBySessionId provides a mock function with given fields: sessionId
func (_m *AccountService) GetUserBySessionId(sessionId string) (*entities.Account, error) {
	ret := _m.Called(sessionId)

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.Account, error)); ok {
		return rf(sessionId)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.Account); ok {
		r0 = rf(sessionId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(sessionId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserBySessionToken provides a mock function with given fields: sessionToken
func (_m *AccountService) GetUserBySessionToken(sessionToken string) (*entities.AccountWithToken, error) {
	ret := _m.Called(sessionToken)

	var r0 *entities.AccountWithToken
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.AccountWithToken, error)); ok {
		return rf(sessionToken)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.AccountWithToken); ok {
		r0 = rf(sessionToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.AccountWithToken)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(sessionToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LoginUserSession provides a mock function with given fields: user
func (_m *AccountService) LoginUserSession(user *entities.Account) (*entities.Session, error) {
	ret := _m.Called(user)

	var r0 *entities.Session
	var r1 error
	if rf, ok := ret.Get(0).(func(*entities.Account) (*entities.Session, error)); ok {
		return rf(user)
	}
	if rf, ok := ret.Get(0).(func(*entities.Account) *entities.Session); ok {
		r0 = rf(user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Session)
		}
	}

	if rf, ok := ret.Get(1).(func(*entities.Account) error); ok {
		r1 = rf(user)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LogoutUserBySessionId provides a mock function with given fields: sessionId
func (_m *AccountService) LogoutUserBySessionId(sessionId string) error {
	ret := _m.Called(sessionId)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(sessionId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LogoutUserBySessionToken provides a mock function with given fields: sessionToken
func (_m *AccountService) LogoutUserBySessionToken(sessionToken string) error {
	ret := _m.Called(sessionToken)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(sessionToken)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RegisterUser provides a mock function with given fields: user
func (_m *AccountService) RegisterUser(user *entities.Account) (*entities.Account, error) {
	ret := _m.Called(user)

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(*entities.Account) (*entities.Account, error)); ok {
		return rf(user)
	}
	if rf, ok := ret.Get(0).(func(*entities.Account) *entities.Account); ok {
		r0 = rf(user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(*entities.Account) error); ok {
		r1 = rf(user)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateJWT provides a mock function with given fields: token
func (_m *AccountService) ValidateJWT(token string) (*entities.CustomClaims, error) {
	ret := _m.Called(token)

	var r0 *entities.CustomClaims
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.CustomClaims, error)); ok {
		return rf(token)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.CustomClaims); ok {
		r0 = rf(token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.CustomClaims)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateLogin provides a mock function with given fields: login
func (_m *AccountService) ValidateLogin(login *entities.Account) error {
	ret := _m.Called(login)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Account) error); ok {
		r0 = rf(login)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewAccountService interface {
	mock.TestingT
	Cleanup(func())
}

// NewAccountService creates a new instance of AccountService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAccountService(t mockConstructorTestingTNewAccountService) *AccountService {
	mock := &AccountService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
