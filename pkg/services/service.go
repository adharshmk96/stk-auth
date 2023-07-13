package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/server/infra"
)

var logger = infra.GetLogger()

type authenticationService struct {
	storage entities.AuthenticationStore
}

func NewUserManagementService(storage entities.AuthenticationStore) entities.AuthenticationService {
	return &authenticationService{
		storage: storage,
	}
}
