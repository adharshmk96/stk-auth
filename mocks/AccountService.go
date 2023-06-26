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

// LoginUserSessionToken provides a mock function with given fields: user
func (_m *AccountService) LoginUserSessionToken(user *entities.Account) (string, error) {
	ret := _m.Called(user)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(*entities.Account) (string, error)); ok {
		return rf(user)
	}
	if rf, ok := ret.Get(0).(func(*entities.Account) string); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(*entities.Account) error); ok {
		r1 = rf(user)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
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
