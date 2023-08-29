// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	ds "github.com/adharshmk96/stk-auth/pkg/entities/ds"

	mock "github.com/stretchr/testify/mock"
)

// accountStore is an autogenerated mock type for the accountStore type
type accountStore struct {
	mock.Mock
}

// DeleteAccountByID provides a mock function with given fields: accountID
func (_m *accountStore) DeleteAccountByID(accountID string) error {
	ret := _m.Called(accountID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(accountID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetAccountByAccountID provides a mock function with given fields: email
func (_m *accountStore) GetAccountByAccountID(email string) (*ds.Account, error) {
	ret := _m.Called(email)

	var r0 *ds.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*ds.Account, error)); ok {
		return rf(email)
	}
	if rf, ok := ret.Get(0).(func(string) *ds.Account); ok {
		r0 = rf(email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ds.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAccountByEmail provides a mock function with given fields: email
func (_m *accountStore) GetAccountByEmail(email string) (*ds.Account, error) {
	ret := _m.Called(email)

	var r0 *ds.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*ds.Account, error)); ok {
		return rf(email)
	}
	if rf, ok := ret.Get(0).(func(string) *ds.Account); ok {
		r0 = rf(email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ds.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAccountByUsername provides a mock function with given fields: username
func (_m *accountStore) GetAccountByUsername(username string) (*ds.Account, error) {
	ret := _m.Called(username)

	var r0 *ds.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*ds.Account, error)); ok {
		return rf(username)
	}
	if rf, ok := ret.Get(0).(func(string) *ds.Account); ok {
		r0 = rf(username)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ds.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAccountList provides a mock function with given fields: limit, offset
func (_m *accountStore) GetAccountList(limit int, offset int) ([]*ds.Account, error) {
	ret := _m.Called(limit, offset)

	var r0 []*ds.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(int, int) ([]*ds.Account, error)); ok {
		return rf(limit, offset)
	}
	if rf, ok := ret.Get(0).(func(int, int) []*ds.Account); ok {
		r0 = rf(limit, offset)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*ds.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(int, int) error); ok {
		r1 = rf(limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTotalAccountsCount provides a mock function with given fields:
func (_m *accountStore) GetTotalAccountsCount() (int64, error) {
	ret := _m.Called()

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func() (int64, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SaveAccount provides a mock function with given fields: account
func (_m *accountStore) SaveAccount(account *ds.Account) error {
	ret := _m.Called(account)

	var r0 error
	if rf, ok := ret.Get(0).(func(*ds.Account) error); ok {
		r0 = rf(account)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAccountByID provides a mock function with given fields: account
func (_m *accountStore) UpdateAccountByID(account *ds.Account) error {
	ret := _m.Called(account)

	var r0 error
	if rf, ok := ret.Get(0).(func(*ds.Account) error); ok {
		r0 = rf(account)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTnewAccountStore interface {
	mock.TestingT
	Cleanup(func())
}

// newAccountStore creates a new instance of accountStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func newAccountStore(t mockConstructorTestingTnewAccountStore) *accountStore {
	mock := &accountStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
