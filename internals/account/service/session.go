package service

import (
	"time"

	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/internals/account/serr"
	"github.com/adharshmk96/stk-auth/server/infra"
	"github.com/google/uuid"
)

func (s *accountService) StartSession(account *domain.Account) (*domain.Session, error) {
	logger := infra.GetLogger()

	sessionId := uuid.New()
	now := time.Now()

	session := &domain.Session{
		ID:        sessionId,
		AccountID: account.ID,
		Active:    true,
		CreatedAt: now,
	}

	err := s.storage.StoreSession(session)
	if err != nil {
		logger.Error("error storing session: ", err)
		return nil, serr.ErrStartingSession
	}

	return session, nil
}

func (s *accountService) EndSession(session string) error {
	logger := infra.GetLogger()

	err := s.storage.DeactivateSession(session)
	if err != nil {
		logger.Error("error updating session: ", err)
		return serr.ErrEndingSession
	}

	return nil
}

func (s *accountService) GetSessionAccount(sessionId string) (*domain.Account, error) {
	logger := infra.GetLogger()

	account, err := s.storage.GetAccountBySessionID(sessionId)
	if err != nil {
		logger.Error("error getting account: ", err)
		return nil, serr.ErrGettingSession
	}

	return account, nil
}
