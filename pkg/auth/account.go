package auth

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
)

type UserID uuid.UUID

func (u *UserID) String() string {
	return uuid.UUID(*u).String()
}

func ParseUserId(id string) (UserID, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return UserID{}, svrerr.ErrParsingUserID
	}
	return UserID(uid), nil
}

type User struct {
	ID        UserID `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Salt      string
	Email     string    `json:"email"`
	Phone     string    `json:"phone"`
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

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AccountGroupAssociation struct {
	UserID    UserID    `json:"user_id"`
	GroupID   string    `json:"group_id"`
	CreatedAt time.Time `json:"created_at"`
}
