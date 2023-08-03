package services

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/google/uuid"
)

func (s *authenticationService) CreateGroup(group *ds.Group) (*ds.Group, error) {
	groupId := uuid.NewString()
	time_now := time.Now()

	group.ID = groupId

	group.CreatedAt = time_now
	group.UpdatedAt = time_now

	err := s.storage.SaveGroup(group)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (s *authenticationService) GetGroupsByUserID(userId ds.AccountID) ([]*ds.Group, error) {
	groups, err := s.storage.GetGroupsByUserID(userId.String())
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (s *authenticationService) UpdateGroupByID(group *ds.Group) error {
	group.UpdatedAt = time.Now()

	err := s.storage.UpdateGroup(group)
	if err != nil {
		return err
	}

	return nil
}

func (s *authenticationService) DeleteGroupByID(groupId string) error {
	err := s.storage.DeleteGroupByID(groupId)
	if err != nil {
		return err
	}

	return nil
}

func (s *authenticationService) AddUserToGroup(userId ds.AccountID, groupId string) error {
	time_now := time.Now()

	groupAssociation := &ds.UserGroupAssociation{
		AccountID: userId,
		GroupID:   groupId,
		CreatedAt: time_now,
	}

	err := s.storage.SaveGroupAssociation(groupAssociation)
	if err != nil {
		return err
	}

	return nil
}

func (s *authenticationService) RemoveUserFromGroup(userId ds.AccountID, groupId string) error {
	err := s.storage.DeleteUserGroupAssociation(userId.String(), groupId)
	if err != nil {
		return err
	}

	return nil
}

func (s *authenticationService) CheckUserInGroup(userId ds.AccountID, groupId string) (bool, error) {
	groupAssociation, err := s.storage.CheckUserGroupAssociation(userId.String(), groupId)
	if err != nil {
		return false, err
	}

	return groupAssociation, nil
}
