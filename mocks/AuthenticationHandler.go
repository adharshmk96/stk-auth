// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	gsk "github.com/adharshmk96/stk/gsk"
	mock "github.com/stretchr/testify/mock"
)

// AuthenticationHandler is an autogenerated mock type for the AuthenticationHandler type
type AuthenticationHandler struct {
	mock.Mock
}

// ChangeCredentials provides a mock function with given fields: gc
func (_m *AuthenticationHandler) ChangeCredentials(gc gsk.Context) {
	_m.Called(gc)
}

// CreateGroup provides a mock function with given fields: gc
func (_m *AuthenticationHandler) CreateGroup(gc gsk.Context) {
	_m.Called(gc)
}

// GetSessionUser provides a mock function with given fields: gc
func (_m *AuthenticationHandler) GetSessionUser(gc gsk.Context) {
	_m.Called(gc)
}

// GetTokenUser provides a mock function with given fields: gc
func (_m *AuthenticationHandler) GetTokenUser(gc gsk.Context) {
	_m.Called(gc)
}

// GetUserList provides a mock function with given fields: gc
func (_m *AuthenticationHandler) GetUserList(gc gsk.Context) {
	_m.Called(gc)
}

// LoginUserSession provides a mock function with given fields: gc
func (_m *AuthenticationHandler) LoginUserSession(gc gsk.Context) {
	_m.Called(gc)
}

// LoginUserToken provides a mock function with given fields: gc
func (_m *AuthenticationHandler) LoginUserToken(gc gsk.Context) {
	_m.Called(gc)
}

// LogoutUser provides a mock function with given fields: gc
func (_m *AuthenticationHandler) LogoutUser(gc gsk.Context) {
	_m.Called(gc)
}

// RegisterUser provides a mock function with given fields: gc
func (_m *AuthenticationHandler) RegisterUser(gc gsk.Context) {
	_m.Called(gc)
}

type mockConstructorTestingTNewAuthenticationHandler interface {
	mock.TestingT
	Cleanup(func())
}

// NewAuthenticationHandler creates a new instance of AuthenticationHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAuthenticationHandler(t mockConstructorTestingTNewAuthenticationHandler) *AuthenticationHandler {
	mock := &AuthenticationHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}