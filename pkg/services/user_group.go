package services

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
)

func (s *authenticationService) AddUserToGroup(userId entities.UserID, groupId string) error {
	time_now := time.Now()

	groupAssociation := &entities.UserGroupAssociation{
		UserID:    userId,
		GroupID:   groupId,
		CreatedAt: time_now,
	}

	err := s.storage.SaveGroupAssociation(groupAssociation)
	if err != nil {
		return err
	}

	return nil
}

func (s *authenticationService) RemoveUserFromGroup(userId entities.UserID, groupId string) error {
	err := s.storage.DeleteUserGroupAssociation(userId.String(), groupId)
	if err != nil {
		return err
	}

	return nil
}

func (s *authenticationService) CheckUserInGroup(userId entities.UserID, groupId string) (bool, error) {
	groupAssociation, err := s.storage.CheckUserGroupAssociation(userId.String(), groupId)
	if err != nil {
		return false, err
	}

	return groupAssociation, nil
}
