// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	entities "github.com/adharshmk96/stk-auth/pkg/entities"
	mock "github.com/stretchr/testify/mock"
)

// GroupStore is an autogenerated mock type for the GroupStore type
type GroupStore struct {
	mock.Mock
}

// CheckUserGroupAssociation provides a mock function with given fields: userID, groupID
func (_m *GroupStore) CheckUserGroupAssociation(userID string, groupID string) (bool, error) {
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
func (_m *GroupStore) DeleteGroupByID(groupID string) error {
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
func (_m *GroupStore) DeleteUserGroupAssociation(userID string, groupID string) error {
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
func (_m *GroupStore) GetGroupByID(groupID string) (*entities.UserGroup, error) {
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
func (_m *GroupStore) GetGroupsByUserID(userID string) ([]*entities.UserGroup, error) {
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

// SaveGroup provides a mock function with given fields: group
func (_m *GroupStore) SaveGroup(group *entities.UserGroup) error {
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
func (_m *GroupStore) SaveGroupAssociation(association *entities.UserGroupAssociation) error {
	ret := _m.Called(association)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.UserGroupAssociation) error); ok {
		r0 = rf(association)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateGroup provides a mock function with given fields: group
func (_m *GroupStore) UpdateGroup(group *entities.UserGroup) error {
	ret := _m.Called(group)

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.UserGroup) error); ok {
		r0 = rf(group)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewGroupStore interface {
	mock.TestingT
	Cleanup(func())
}

// NewGroupStore creates a new instance of GroupStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewGroupStore(t mockConstructorTestingTNewGroupStore) *GroupStore {
	mock := &GroupStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
