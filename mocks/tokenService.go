// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	entities "github.com/adharshmk96/stk-auth/pkg/entities"
	mock "github.com/stretchr/testify/mock"
)

// tokenService is an autogenerated mock type for the tokenService type
type tokenService struct {
	mock.Mock
}

// GenerateJWT provides a mock function with given fields: claims
func (_m *tokenService) GenerateJWT(claims *entities.CustomClaims) (string, error) {
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

// ValidateJWT provides a mock function with given fields: token
func (_m *tokenService) ValidateJWT(token string) (*entities.CustomClaims, error) {
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

type mockConstructorTestingTnewTokenService interface {
	mock.TestingT
	Cleanup(func())
}

// newTokenService creates a new instance of tokenService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func newTokenService(t mockConstructorTestingTnewTokenService) *tokenService {
	mock := &tokenService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}