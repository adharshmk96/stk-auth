// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	entities "github.com/adharshmk96/stk-auth/pkg/entities"
	mock "github.com/stretchr/testify/mock"
)

// UserService is an autogenerated mock type for the UserService type
type UserService struct {
	mock.Mock
}

// Authenticate provides a mock function with given fields: login
func (_m *UserService) Authenticate(login *entities.User) error {
	ret := _m.Called(login)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.User) error); ok {
		r0 = rf(login)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ChangePassword provides a mock function with given fields: user
func (_m *UserService) ChangePassword(user *entities.User) error {
	ret := _m.Called(user)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.User) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateUser provides a mock function with given fields: user
func (_m *UserService) CreateUser(user *entities.User) (*entities.User, error) {
	ret := _m.Called(user)

	var r0 *entities.User
	var r1 error
	if rf, ok := ret.Get(0).(func(*entities.User) (*entities.User, error)); ok {
		return rf(user)
	}
	if rf, ok := ret.Get(0).(func(*entities.User) *entities.User); ok {
		r0 = rf(user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.User)
		}
	}

	if rf, ok := ret.Get(1).(func(*entities.User) error); ok {
		r1 = rf(user)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByID provides a mock function with given fields: userId
func (_m *UserService) GetUserByID(userId string) (*entities.User, error) {
	ret := _m.Called(userId)

	var r0 *entities.User
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.User, error)); ok {
		return rf(userId)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.User); ok {
		r0 = rf(userId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.User)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(userId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewUserService interface {
	mock.TestingT
	Cleanup(func())
}

// NewUserService creates a new instance of UserService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewUserService(t mockConstructorTestingTNewUserService) *UserService {
	mock := &UserService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
