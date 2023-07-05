// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	entities "github.com/adharshmk96/stk-auth/pkg/entities"
	mock "github.com/stretchr/testify/mock"
)

// UserManagementService is an autogenerated mock type for the UserManagementService type
type UserManagementService struct {
	mock.Mock
}

// Authenticate provides a mock function with given fields: login
func (_m *UserManagementService) Authenticate(login *entities.Account) error {
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
func (_m *UserManagementService) ChangePassword(user *entities.Account) error {
	ret := _m.Called(user)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Account) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateGroup provides a mock function with given fields: group
func (_m *UserManagementService) CreateGroup(group *entities.UserGroup) (*entities.UserGroup, error) {
	ret := _m.Called(group)

	var r0 *entities.UserGroup
	var r1 error
	if rf, ok := ret.Get(0).(func(*entities.UserGroup) (*entities.UserGroup, error)); ok {
		return rf(group)
	}
	if rf, ok := ret.Get(0).(func(*entities.UserGroup) *entities.UserGroup); ok {
		r0 = rf(group)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.UserGroup)
		}
	}

	if rf, ok := ret.Get(1).(func(*entities.UserGroup) error); ok {
		r1 = rf(group)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateSession provides a mock function with given fields: user
func (_m *UserManagementService) CreateSession(user *entities.Account) (*entities.Session, error) {
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

// CreateUser provides a mock function with given fields: user
func (_m *UserManagementService) CreateUser(user *entities.Account) (*entities.Account, error) {
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

// GenerateJWT provides a mock function with given fields: claims
func (_m *UserManagementService) GenerateJWT(claims *entities.CustomClaims) (string, error) {
	ret := _m.Called(claims)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(*entities.CustomClaims) (string, error)); ok {
		return rf(claims)
	}
	if rf, ok := ret.Get(0).(func(*entities.CustomClaims) string); ok {
		r0 = rf(claims)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(*entities.CustomClaims) error); ok {
		r1 = rf(claims)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByID provides a mock function with given fields: userId
func (_m *UserManagementService) GetUserByID(userId string) (*entities.Account, error) {
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

// GetUserBySessionId provides a mock function with given fields: sessionId
func (_m *UserManagementService) GetUserBySessionId(sessionId string) (*entities.Account, error) {
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

// LogoutUserBySessionId provides a mock function with given fields: sessionId
func (_m *UserManagementService) LogoutUserBySessionId(sessionId string) error {
	ret := _m.Called(sessionId)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(sessionId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateJWT provides a mock function with given fields: token
func (_m *UserManagementService) ValidateJWT(token string) (*entities.CustomClaims, error) {
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

type mockConstructorTestingTNewUserManagementService interface {
	mock.TestingT
	Cleanup(func())
}

// NewUserManagementService creates a new instance of UserManagementService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewUserManagementService(t mockConstructorTestingTNewUserManagementService) *UserManagementService {
	mock := &UserManagementService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
