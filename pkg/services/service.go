package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/golang-jwt/jwt/v5"
)

var logger = infra.GetLogger()

type accountService struct {
	storage entities.AccountStore
}

type customClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	jwt.RegisteredClaims
}

func NewAccountService(storage entities.AccountStore) entities.AccountService {
	return &accountService{
		storage: storage,
	}
}
