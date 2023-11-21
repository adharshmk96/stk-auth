package domain

import (
	"time"

	"github.com/google/uuid"
)

type AccountID uuid.UUID

func NewAccountID() AccountID {
	return AccountID(uuid.New())
}

// String representation is stored in sqlite3
func (id AccountID) String() string {
	return uuid.UUID(id).String()
}

func ParseAccountID(s string) (AccountID, error) {
	parsed, err := uuid.Parse(s)
	return AccountID(parsed), err
}

type Account struct {
	ID        AccountID `json:"id"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Salt      string    `json:"salt"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Session struct {
	ID        uuid.UUID `json:"id"`
	AccountID AccountID `json:"account_id"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

func NewSessionID() uuid.UUID {
	return uuid.New()
}
