package service

import (
	"errors"
	"time"

	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/internals/account/serr"
	"github.com/adharshmk96/stk-auth/server/infra"
	"github.com/adharshmk96/stk/pkg/utils"
)

func (s *accountService) CreateAccount(account *domain.Account) error {
	logger := infra.GetLogger()

	accountId := domain.NewAccountID()
	now := time.Now()

	salt, err := utils.GenerateSalt()
	if err != nil {
		logger.Error("error generating salt: ", err)
		return serr.ErrHasingPassword
	}

	hashedPassword, hashedSalt := utils.HashPassword(account.Password, salt)

	account.ID = accountId
	account.Password = hashedPassword
	account.Salt = hashedSalt
	account.CreatedAt = now
	account.UpdatedAt = now

	err = s.storage.StoreAccount(account)
	if err != nil {
		if errors.Is(err, serr.ErrUniqueConstraint) {
			return serr.ErrAccountExists
		}
		return err
	}

	return nil
}

func (s *accountService) GetAccountByEmail(email string) (*domain.Account, error) {
	return s.storage.GetAccountByEmail(email)
}
