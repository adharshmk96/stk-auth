// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	entities "github.com/adharshmk96/stk-auth/pkg/entities"
	mock "github.com/stretchr/testify/mock"
)

// AccountStore is an autogenerated mock type for the AccountStore type
type AccountStore struct {
	mock.Mock
}

// GetSessionByID provides a mock function with given fields: sessionID
func (_m *AccountStore) GetSessionByID(sessionID string) (*entities.Session, error) {
	ret := _m.Called(sessionID)

	var r0 *entities.Session
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.Session, error)); ok {
		return rf(sessionID)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.Session); ok {
		r0 = rf(sessionID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Session)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(sessionID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByEmail provides a mock function with given fields: email
func (_m *AccountStore) GetUserByEmail(email string) (*entities.Account, error) {
	ret := _m.Called(email)

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.Account, error)); ok {
		return rf(email)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.Account); ok {
		r0 = rf(email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserBySessionID provides a mock function with given fields: sessionID
func (_m *AccountStore) GetUserBySessionID(sessionID string) (*entities.Account, error) {
	ret := _m.Called(sessionID)

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.Account, error)); ok {
		return rf(sessionID)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.Account); ok {
		r0 = rf(sessionID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(sessionID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByUserID provides a mock function with given fields: email
func (_m *AccountStore) GetUserByUserID(email string) (*entities.Account, error) {
	ret := _m.Called(email)

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.Account, error)); ok {
		return rf(email)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.Account); ok {
		r0 = rf(email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByUsername provides a mock function with given fields: username
func (_m *AccountStore) GetUserByUsername(username string) (*entities.Account, error) {
	ret := _m.Called(username)

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.Account, error)); ok {
		return rf(username)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.Account); ok {
		r0 = rf(username)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InvalidateSessionByID provides a mock function with given fields: sessionID
func (_m *AccountStore) InvalidateSessionByID(sessionID string) error {
	ret := _m.Called(sessionID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(sessionID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveSession provides a mock function with given fields: session
func (_m *AccountStore) SaveSession(session *entities.Session) error {
	ret := _m.Called(session)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Session) error); ok {
		r0 = rf(session)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveUser provides a mock function with given fields: user
func (_m *AccountStore) SaveUser(user *entities.Account) error {
	ret := _m.Called(user)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Account) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateUserByID provides a mock function with given fields: user
func (_m *AccountStore) UpdateUserByID(user *entities.Account) error {
	ret := _m.Called(user)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Account) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewAccountStore interface {
	mock.TestingT
	Cleanup(func())
}

// NewAccountStore creates a new instance of AccountStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAccountStore(t mockConstructorTestingTNewAccountStore) *AccountStore {
	mock := &AccountStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
