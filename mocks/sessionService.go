// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	ds "github.com/adharshmk96/stk-auth/pkg/entities/ds"

	mock "github.com/stretchr/testify/mock"
)

// sessionService is an autogenerated mock type for the sessionService type
type sessionService struct {
	mock.Mock
}

// CreateSession provides a mock function with given fields: account
func (_m *sessionService) CreateSession(account *ds.Account) (*ds.Session, error) {
	ret := _m.Called(account)

	var r0 *ds.Session
	var r1 error
	if rf, ok := ret.Get(0).(func(*ds.Account) (*ds.Session, error)); ok {
		return rf(account)
	}
	if rf, ok := ret.Get(0).(func(*ds.Account) *ds.Session); ok {
		r0 = rf(account)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ds.Session)
		}
	}

	if rf, ok := ret.Get(1).(func(*ds.Account) error); ok {
		r1 = rf(account)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAccountBySessionId provides a mock function with given fields: sessionId
func (_m *sessionService) GetAccountBySessionId(sessionId string) (*ds.Account, error) {
	ret := _m.Called(sessionId)

	var r0 *ds.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*ds.Account, error)); ok {
		return rf(sessionId)
	}
	if rf, ok := ret.Get(0).(func(string) *ds.Account); ok {
		r0 = rf(sessionId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ds.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(sessionId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LogoutAccountBySessionId provides a mock function with given fields: sessionId
func (_m *sessionService) LogoutAccountBySessionId(sessionId string) error {
	ret := _m.Called(sessionId)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(sessionId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTnewSessionService interface {
	mock.TestingT
	Cleanup(func())
}

// newSessionService creates a new instance of sessionService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func newSessionService(t mockConstructorTestingTnewSessionService) *sessionService {
	mock := &sessionService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
