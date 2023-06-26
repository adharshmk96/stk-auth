package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk-auth/pkg/storage"
)

var logger = infra.GetLogger()

type accountService struct {
	storage storage.AccountStore
}

type AccountService interface {
	RegisterUser(user *entities.Account) (*entities.Account, error)
	LoginUserSession(user *entities.Account) (*entities.Session, error)
	LoginUserSessionToken(user *entities.Account) (string, error)
	GetUserBySessionId(sessionId string) (*entities.Account, error)
}

func NewAccountService(storage storage.AccountStore) AccountService {
	return &accountService{
		storage: storage,
	}
}
