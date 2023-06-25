package services

import (
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/infra"
	"github.com/adharshmk96/auth-server/pkg/storage"
)

var logger = infra.GetLogger()

type accountService struct {
	storage storage.AccountStore
}

type AccountService interface {
	RegisterUser(user *entities.Account) (*entities.Account, error)
	LoginUserSession(user *entities.Account) (*entities.Session, error)
}

func NewAccountService(storage storage.AccountStore) AccountService {
	return &accountService{
		storage: storage,
	}
}
