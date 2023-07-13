// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	entities "github.com/adharshmk96/stk-auth/pkg/entities"
	mock "github.com/stretchr/testify/mock"
)

// AuthenticationStore is an autogenerated mock type for the AuthenticationStore type
type AuthenticationStore struct {
	mock.Mock
}

// CheckUserGroupAssociation provides a mock function with given fields: userID, groupID
func (_m *AuthenticationStore) CheckUserGroupAssociation(userID string, groupID string) (bool, error) {
	ret := _m.Called(userID, groupID)

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string) (bool, error)); ok {
		return rf(userID, groupID)
	}
	if rf, ok := ret.Get(0).(func(string, string) bool); ok {
		r0 = rf(userID, groupID)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(userID, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteGroupByID provides a mock function with given fields: groupID
func (_m *AuthenticationStore) DeleteGroupByID(groupID string) error {
	ret := _m.Called(groupID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(groupID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteUserGroupAssociation provides a mock function with given fields: userID, groupID
func (_m *AuthenticationStore) DeleteUserGroupAssociation(userID string, groupID string) error {
	ret := _m.Called(userID, groupID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(userID, groupID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetGroupByID provides a mock function with given fields: groupID
func (_m *AuthenticationStore) GetGroupByID(groupID string) (*entities.UserGroup, error) {
	ret := _m.Called(groupID)

	var r0 *entities.UserGroup
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*entities.UserGroup, error)); ok {
		return rf(groupID)
	}
	if rf, ok := ret.Get(0).(func(string) *entities.UserGroup); ok {
		r0 = rf(groupID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.UserGroup)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetGroupsByUserID provides a mock function with given fields: userID
func (_m *AuthenticationStore) GetGroupsByUserID(userID string) ([]*entities.UserGroup, error) {
	ret := _m.Called(userID)

	var r0 []*entities.UserGroup
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]*entities.UserGroup, error)); ok {
		return rf(userID)
	}
	if rf, ok := ret.Get(0).(func(string) []*entities.UserGroup); ok {
		r0 = rf(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*entities.UserGroup)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetSessionByID provides a mock function with given fields: sessionID
func (_m *AuthenticationStore) GetSessionByID(sessionID string) (*entities.Session, error) {
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
func (_m *AuthenticationStore) GetUserByEmail(email string) (*entities.Account, error) {
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
func (_m *AuthenticationStore) GetUserBySessionID(sessionID string) (*entities.Account, error) {
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
func (_m *AuthenticationStore) GetUserByUserID(email string) (*entities.Account, error) {
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
func (_m *AuthenticationStore) GetUserByUsername(username string) (*entities.Account, error) {
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

// GetUserList provides a mock function with given fields: limit, offset
func (_m *AuthenticationStore) GetUserList(limit int, offset int) ([]*entities.Account, error) {
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

// InvalidateSessionByID provides a mock function with given fields: sessionID
func (_m *AuthenticationStore) InvalidateSessionByID(sessionID string) error {
	ret := _m.Called(sessionID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(sessionID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveGroup provides a mock function with given fields: group
func (_m *AuthenticationStore) SaveGroup(group *entities.UserGroup) error {
	ret := _m.Called(group)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.UserGroup) error); ok {
		r0 = rf(group)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveGroupAssociation provides a mock function with given fields: association
func (_m *AuthenticationStore) SaveGroupAssociation(association *entities.UserGroupAssociation) error {
	ret := _m.Called(association)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.UserGroupAssociation) error); ok {
		r0 = rf(association)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveSession provides a mock function with given fields: session
func (_m *AuthenticationStore) SaveSession(session *entities.Session) error {
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
func (_m *AuthenticationStore) SaveUser(user *entities.Account) error {
	ret := _m.Called(user)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Account) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateGroup provides a mock function with given fields: group
func (_m *AuthenticationStore) UpdateGroup(group *entities.UserGroup) error {
	ret := _m.Called(group)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.UserGroup) error); ok {
		r0 = rf(group)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateUserByID provides a mock function with given fields: user
func (_m *AuthenticationStore) UpdateUserByID(user *entities.Account) error {
	ret := _m.Called(user)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Account) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewAuthenticationStore interface {
	mock.TestingT
	Cleanup(func())
}

// NewAuthenticationStore creates a new instance of AuthenticationStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAuthenticationStore(t mockConstructorTestingTNewAuthenticationStore) *AuthenticationStore {
	mock := &AuthenticationStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}