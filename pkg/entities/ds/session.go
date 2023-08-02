package ds

import "time"

type Session struct {
	UserID    UserID    `json:"user_id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Valid     bool      `json:"valid"`
}
