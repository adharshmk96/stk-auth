package service

import (
	"github.com/adharshmk96/stk-auth/internals/account/domain"
)

type accountService struct {
	storage domain.AccountStorage
}

func NewAccountService(storage domain.AccountStorage) domain.AccountService {
	return &accountService{
		storage: storage,
	}
}
