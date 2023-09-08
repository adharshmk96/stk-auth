package entities

import (
	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	AccountID string `json:"account_id"`
	jwt.RegisteredClaims
}

type tokenService interface {
	GenerateJWT(claims *CustomClaims) (string, error)
	ValidateJWT(token string) (*CustomClaims, error)
}
type accountService interface {
	CreateAccount(account *ds.Account) (*ds.Account, error)
	Authenticate(login *ds.Account) error
	ChangePassword(account *ds.Account) error
	SendPasswordResetEmail(email string) error
	ResetPassword(account string, password string) error
	GetAccountByID(accountId string) (*ds.Account, error)
	// GetAccountByEmail(email string) (*ds.Account, error)

	// Admin methods
	GetAccountList(limit int, offset int) ([]*ds.Account, error)
	GetTotalAccountsCount() (int64, error)
	GetAccountDetails(accountId ds.AccountID) (*ds.Account, error)
}

type sessionService interface {
	CreateSession(account *ds.Account) (*ds.Session, error)
	GetAccountBySessionId(sessionId string) (*ds.Account, error)
	LogoutAccountBySessionId(sessionId string) error
}

type groupService interface {
	CreateGroup(group *ds.Group) (*ds.Group, error)
	GetGroupsByAccountID(accountId ds.AccountID) ([]*ds.Group, error)
	UpdateGroupByID(group *ds.Group) error
	DeleteGroupByID(groupId string) error
	AddAccountToGroup(accountId ds.AccountID, groupId string) error
	RemoveAccountFromGroup(accountId ds.AccountID, groupId string) error
	CheckAccountInGroup(accountId ds.AccountID, groupId string) (bool, error)
}

type AuthenticationService interface {
	accountService
	sessionService
	groupService
	tokenService
}
