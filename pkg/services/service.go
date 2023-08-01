package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/server/infra"
)

var logger = infra.GetLogger()

type authenticationService struct {
	storage entities.AuthenticationStore
}

func NewAuthenticationService(storage entities.AuthenticationStore) entities.AuthenticationService {
	return &authenticationService{
		storage: storage,
	}
}

type adminService struct {
	storage entities.AuthenticationStore
}

func NewAdminService(storage entities.AuthenticationStore) entities.AdminService {
	return &adminService{
		storage: storage,
	}
}
