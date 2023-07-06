package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
)

var logger = infra.GetLogger()

type userManagementService struct {
	storage entities.UserManagementStore
}

func NewAccountService(storage entities.UserManagementStore) entities.UserManagementService {
	return &userManagementService{
		storage: storage,
	}
}
