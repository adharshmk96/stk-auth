// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	stk "github.com/adharshmk96/stk"
	mock "github.com/stretchr/testify/mock"
)

// AccountHandler is an autogenerated mock type for the AccountHandler type
type AccountHandler struct {
	mock.Mock
}

// GetUserByID provides a mock function with given fields: ctx
func (_m *AccountHandler) GetUserByID(ctx stk.Context) {
	_m.Called(ctx)
}

// LoginUserSession provides a mock function with given fields: ctx
func (_m *AccountHandler) LoginUserSession(ctx stk.Context) {
	_m.Called(ctx)
}

// RegisterUser provides a mock function with given fields: ctx
func (_m *AccountHandler) RegisterUser(ctx stk.Context) {
	_m.Called(ctx)
}

type mockConstructorTestingTNewAccountHandler interface {
	mock.TestingT
	Cleanup(func())
}

// NewAccountHandler creates a new instance of AccountHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAccountHandler(t mockConstructorTestingTNewAccountHandler) *AccountHandler {
	mock := &AccountHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
