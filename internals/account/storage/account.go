package storage

import (
	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/internals/account/serr"
	"github.com/adharshmk96/stk-auth/server/infra"
)

const (
	UNIQUE_CONSTRAINT = "UNIQUE constraint failed: account.email"
)

func (s *sqliteRepo) StoreAccount(account *domain.Account) error {
	logger := infra.GetLogger()

	stmt, err := s.conn.Prepare(INSERT_ACCOUNT)
	if err != nil {
		logger.Error(err.Error())
		return serr.ErrInsertAccountFailed
	}

	result, err := stmt.Exec(
		account.ID.String(),
		account.Username,
		account.Email,
		account.Password,
		account.Salt,
		account.FirstName,
		account.LastName,
		account.CreatedAt,
		account.UpdatedAt,
	)

	if err != nil {
		if err.Error() == UNIQUE_CONSTRAINT {
			logger.Error(err.Error())
			return serr.ErrUniqueConstraint
		}
		logger.Error(err.Error())
		return serr.ErrInsertAccountFailed
	}

	_, err = result.LastInsertId()
	if err != nil {
		logger.Error(err.Error())
		return serr.ErrInsertAccountFailed
	}

	return nil
}

func (s *sqliteRepo) GetAccountByEmail(email string) (*domain.Account, error) {
	logger := infra.GetLogger()

	stmt, err := s.conn.Prepare(GET_ACCOUNT_BY_EMAIL)
	if err != nil {
		logger.Error(err.Error())
		return nil, serr.ErrGetAccountFailed
	}

	row := stmt.QueryRow(email)

	var account domain.Account
	var accountId string
	err = row.Scan(
		&accountId,
		&account.Username,
		&account.Email,
		&account.Password,
		&account.Salt,
		&account.FirstName,
		&account.LastName,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err != nil {
		logger.Error(err.Error())
		return nil, serr.ErrAccountFailed
	}

	account.ID, err = domain.ParseAccountID(accountId)
	if err != nil {
		logger.Error(err.Error())
		return nil, serr.ErrAccountFailed
	}

	return &account, nil
}
