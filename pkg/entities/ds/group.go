package ds

import (
	"time"
)

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type UserGroupAssociation struct {
	AccountID AccountID `json:"user_id"`
	GroupID   string    `json:"group_id"`
	CreatedAt time.Time `json:"created_at"`
}
