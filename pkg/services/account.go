package services

import (
	"time"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/infra"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk/utils"
	"github.com/google/uuid"
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

func (u *accountService) RegisterUser(user *entities.Account) (*entities.Account, error) {
	salt, err := utils.GenerateSalt()
	if err != nil {
		logger.Error("error generating salt: ", err)
		return nil, svrerr.ErrHasingPassword
	}

	hashedPassword, hashedSalt := utils.HashPassword(user.Password, salt)

	current_timestamp := time.Now()
	newUserId := uuid.New()

	user.ID = entities.UserID(newUserId)
	user.CreatedAt = current_timestamp
	user.UpdatedAt = current_timestamp
	user.Password = hashedPassword
	user.Salt = hashedSalt

	if err = u.storage.SaveUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (u *accountService) GetUserByID(id entities.UserID) (*entities.Account, error) {
	user, err := u.storage.GetUserByID(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}
