package entities

import (
	"time"

	"github.com/google/uuid"
)

type UserID uuid.UUID

func (u *UserID) String() string {
	return uuid.UUID(*u).String()
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

type AccountService interface {
	// Create a new user
	RegisterUser(user *Account) (*Account, error)
	// Get a user by id
	GetUserByID(id UserID) (*Account, error)
}

type AccountStore interface {
	// Create a new user
	SaveUser(user *Account) error
	// Get a user by id
	GetUserByID(id UserID) (*Account, error)
	// // Get a user by username
	// GetUserByUsername(username string) (*User, error)
	// // Get a user by email
	// GetUserByEmail(email string) (*User, error)
	// // Update a user
	// UpdateUser(user *User) error
	// // Delete a user
	// DeleteUser(id int64) error
}
