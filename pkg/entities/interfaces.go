package entities

import "github.com/adharshmk96/stk"

type AccountHandler interface {
	RegisterUser(ctx stk.Context)
	LoginUserSession(ctx stk.Context)
	LoginUserSessionToken(ctx stk.Context)
	GetSessionUser(ctx stk.Context)
	GetSessionTokenUser(ctx stk.Context)
	LogoutUser(ctx stk.Context)
}

type AccountService interface {
	RegisterUser(user *Account) (*Account, error)
	LoginUserSession(user *Account) (*Session, error)
	LoginUserSessionToken(user *Account) (string, error)
	GetUserBySessionId(sessionId string) (*Account, error)
	GetUserBySessionToken(sessionToken string) (*AccountWithToken, error)
	LogoutUserBySessionId(sessionId string) error
	LogoutUserBySessionToken(sessionToken string) error
}

type AccountStore interface {
	SaveUser(user *Account) error
	GetUserByUserID(email string) (*Account, error)
	GetUserByEmail(email string) (*Account, error)
	GetUserByUsername(username string) (*Account, error)
	SaveSession(session *Session) error
	GetSessionByID(sessionID string) (*Session, error)
	GetUserBySessionID(sessionID string) (*Account, error)
	InvalidateSessionByID(sessionID string) error
}
