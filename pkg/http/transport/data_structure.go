package transport

import (
	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
	"time"
)

type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Groups    []string  `json:"groups,omitempty"`
}

type UserListResponse struct {
	Total int64          `json:"total"`
	Data  []UserResponse `json:"data"`
}

type CredentialUpdateRequest struct {
	Credentials    *ds.User `json:"credentials"`
	NewCredentials *ds.User `json:"updated_credentials"`
}

type GroupResponse = ds.Group
