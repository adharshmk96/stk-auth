package entities

import "github.com/adharshmk96/stk/gsk"

type AccountHandler interface {
	RegisterUser(ctx gsk.Context)
	LoginUserSession(ctx gsk.Context)
	LoginUserSessionToken(ctx gsk.Context)
	GetSessionUser(ctx gsk.Context)
	GetSessionTokenUser(ctx gsk.Context)
	LogoutUser(ctx gsk.Context)
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
