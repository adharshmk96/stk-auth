package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
)

var logger = infra.GetLogger()

type accountService struct {
	storage entities.AccountStore
}

func NewAccountService(storage entities.AccountStore) entities.AccountService {
	return &accountService{
		storage: storage,
	}
}
