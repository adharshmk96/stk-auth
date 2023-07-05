package services

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/google/uuid"
)

func (s *accountService) CreateGroup(group *entities.UserGroup) (*entities.UserGroup, error) {
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

func (s *accountService) AddUserToGroup(userId entities.UserID, groupId string) error {
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
