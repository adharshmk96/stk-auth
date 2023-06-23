package entities

import "github.com/google/uuid"

type UserID uuid.UUID

type User struct {
	ID       UserID `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type UserService interface {
	// Create a new user
	RegisterUser(user *User) (*User, error)
	// Get a user by id
	GetUserByID(id UserID) (*User, error)
}

type UserStore interface {
	// Create a new user
	SaveUser(user *User) (*User, error)
	// Get a user by id
	GetUserByID(id UserID) (*User, error)
	// // Get a user by username
	// GetUserByUsername(username string) (*User, error)
	// // Get a user by email
	// GetUserByEmail(email string) (*User, error)
	// // Update a user
	// UpdateUser(user *User) error
	// // Delete a user
	// DeleteUser(id int64) error
}
