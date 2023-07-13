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

// Authenticate provides a mock function with given fields: login
func (_m *AccountService) Authenticate(login *entities.Account) error {
	ret := _m.Called(login)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Account) error); ok {
		r0 = rf(login)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ChangePassword provides a mock function with given fields: user
func (_m *AccountService) ChangePassword(user *entities.Account) error {
	ret := _m.Called(user)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Account) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateUser provides a mock function with given fields: user
func (_m *AccountService) CreateUser(user *entities.Account) (*entities.Account, error) {
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

// GetUserByID provides a mock function with given fields: userId
func (_m *AccountService) GetUserByID(userId string) (*entities.Account, error) {
	ret := _m.Called(userId)

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.Account, error)); ok {
		return rf(userId)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.Account); ok {
		r0 = rf(userId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(userId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserList provides a mock function with given fields: limit, offset
func (_m *AccountService) GetUserList(limit int, offset int) ([]*entities.Account, error) {
	ret := _m.Called(limit, offset)

	var r0 []*entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(int, int) ([]*entities.Account, error)); ok {
		return rf(limit, offset)
	}
	if rf, ok := ret.Get(0).(func(int, int) []*entities.Account); ok {
		r0 = rf(limit, offset)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(int, int) error); ok {
		r1 = rf(limit, offset)
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
