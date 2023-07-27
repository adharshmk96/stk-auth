package services

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/google/uuid"
)

func (s *authenticationService) CreateGroup(group *entities.Group) (*entities.Group, error) {
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

func (s *authenticationService) GetGroupsByUserID(userId entities.UserID) ([]*entities.Group, error) {
	groups, err := s.storage.GetGroupsByUserID(userId.String())
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (s *authenticationService) UpdateGroupByID(group *entities.Group) error {
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
