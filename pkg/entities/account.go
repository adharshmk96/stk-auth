package entities

import (
	"time"

	"github.com/google/uuid"
)

type UserID uuid.UUID

func (u *UserID) String() string {
	return uuid.UUID(*u).String()
}

func ParseUserId(id string) (UserID, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return UserID{}, ErrParsingUserID
	}
	return UserID(uid), nil
}

type Account struct {
	ID        UserID `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Salt      string
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Session struct {
	UserID    UserID    `json:"user_id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Valid     bool      `json:"valid"`
}
