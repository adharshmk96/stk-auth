// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	gsk "github.com/adharshmk96/stk/gsk"
	mock "github.com/stretchr/testify/mock"
)

// accountHandler is an autogenerated mock type for the accountHandler type
type accountHandler struct {
	mock.Mock
}

// ChangeCredentials provides a mock function with given fields: gc
func (_m *accountHandler) ChangeCredentials(gc *gsk.Context) {
	_m.Called(gc)
}

// RegisterAccount provides a mock function with given fields: gc
func (_m *accountHandler) RegisterAccount(gc *gsk.Context) {
	_m.Called(gc)
}

type mockConstructorTestingTnewAccountHandler interface {
	mock.TestingT
	Cleanup(func())
}

// newAccountHandler creates a new instance of accountHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func newAccountHandler(t mockConstructorTestingTnewAccountHandler) *accountHandler {
	mock := &accountHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
