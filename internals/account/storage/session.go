package storage

import (
	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/server/infra"
)

func (s *sqliteRepo) StoreSession(session *domain.Session) error {
	logger := infra.GetLogger()

	stmt, err := s.conn.Prepare(INSERT_SESSION)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	res, err := stmt.Exec(session.ID.String(), session.AccountID.String(), session.Active, session.CreatedAt)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	_, err = res.LastInsertId()
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func (s *sqliteRepo) GetSessionByID(id string) (*domain.Session, error) {
	logger := infra.GetLogger()

	stmt, err := s.conn.Prepare(GET_SESSION_BY_ID)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	row := stmt.QueryRow(id)

	session := &domain.Session{}
	err = row.Scan(&session.ID, &session.AccountID, &session.Active, &session.CreatedAt)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return session, nil
}

func (s *sqliteRepo) GetAccountBySessionID(id string) (*domain.Account, error) {
	logger := infra.GetLogger()

	stmt, err := s.conn.Prepare(GET_ACCOUNT_BY_SESSION_ID)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	row := stmt.QueryRow(id)

	var accountId string
	account := &domain.Account{}
	err = row.Scan(
		&accountId,
		&account.Username,
		&account.Email,
		&account.Password,
		&account.Salt,
		&account.CreatedAt,
		&account.UpdatedAt,
	)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	account.ID, err = domain.ParseAccountID(accountId)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return account, nil
}

func (s *sqliteRepo) UpdateSession(session *domain.Session) error {
	logger := infra.GetLogger()

	stmt, err := s.conn.Prepare(UPDATE_SESSION)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	_, err = stmt.Exec(session.Active, session.ID)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func (s *sqliteRepo) DeactivateSession(id string) error {
	logger := infra.GetLogger()

	stmt, err := s.conn.Prepare(DEACTIVATE_SESSION)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	_, err = stmt.Exec(id)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}
