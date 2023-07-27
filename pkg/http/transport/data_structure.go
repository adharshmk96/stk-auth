package transport

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
)

type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UserListResponse struct {
	Total int64          `json:"total"`
	Data  []UserResponse `json:"data"`
}

type CredentialUpdateRequest struct {
	Credentials    *entities.User `json:"credentials"`
	NewCredentials *entities.User `json:"updated_credentials"`
}

type GroupResponse = entities.Group
