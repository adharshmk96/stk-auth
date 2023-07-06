package services

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/google/uuid"
)

func (s *userManagementService) CreateGroup(group *entities.UserGroup) (*entities.UserGroup, error) {
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

func (s *userManagementService) GetGroupsByUserID(userId entities.UserID) ([]*entities.UserGroup, error) {
	groups, err := s.storage.GetGroupsByUserID(userId.String())
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (s *userManagementService) UpdateGroupByID(group *entities.UserGroup) error {
	group.UpdatedAt = time.Now()

	err := s.storage.UpdateGroup(group)
	if err != nil {
		return err
	}

	return nil
}

func (s *userManagementService) DeleteGroupByID(groupId string) error {
	err := s.storage.DeleteGroupByID(groupId)
	if err != nil {
		return err
	}

	return nil
}
