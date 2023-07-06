package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/server/infra"
)

var logger = infra.GetLogger()

type userManagementService struct {
	storage entities.UserManagementStore
}

func NewUserManagementService(storage entities.UserManagementStore) entities.UserManagementService {
	return &userManagementService{
		storage: storage,
	}
}
