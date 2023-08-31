package ds

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
)

type AccountID uuid.UUID

func (u *AccountID) String() string {
	return uuid.UUID(*u).String()
}

func ParseAccountId(id string) (AccountID, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return AccountID{}, svrerr.ErrParsingAccountID
	}
	return AccountID(uid), nil
}

type Account struct {
	ID        AccountID `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Salt      string
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PasswordResetToken struct {
	AccountID string
	Token     string
	Expiry    time.Time
}
