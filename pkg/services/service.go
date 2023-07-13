package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/server/infra"
)

var logger = infra.GetLogger()

type userManagementService struct {
	storage entities.AuthenticationStore
}

func NewUserManagementService(storage entities.AuthenticationStore) entities.AuthenticationService {
	return &userManagementService{
		storage: storage,
	}
}
