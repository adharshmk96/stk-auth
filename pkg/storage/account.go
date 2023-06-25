package storage

import "github.com/adharshmk96/auth-server/pkg/entities"

type AccountStore interface {
	// Create a new user
	SaveUser(user *entities.Account) error
	// Get a user by id
	GetUserByID(id entities.UserID) (*entities.Account, error)
	// // Get a user by username
	// GetUserByUsername(username string) (*User, error)
	// // Get a user by email
	GetUserByEmail(email string) (*entities.Account, error)
	// // Update a user
	// UpdateUser(user *User) error
	// // Delete a user
	// DeleteUser(id int64) error
}
