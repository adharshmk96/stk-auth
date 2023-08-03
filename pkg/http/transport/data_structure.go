package transport

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
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
	Credentials    *ds.Account `json:"credentials"`
	NewCredentials *ds.Account `json:"updated_credentials"`
}

type GroupResponse = ds.Group
