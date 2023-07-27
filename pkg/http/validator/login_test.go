package validator

import (
	"testing"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/stretchr/testify/assert"
)

func TestValidateLogin(t *testing.T) {
	tests := []struct {
		name  string
		login *entities.User
		err   bool
	}{
		{
			name: "Username and password",
			login: &entities.User{
				Username: "TestUser",
				Password: "Test$123",
			},
			err: false,
		},
		{
			name: "Email and password",
			login: &entities.User{
				Email:    "user@email.com",
				Password: "Test$123",
			},
			err: false,
		},
		{
			name: "Empty password",
			login: &entities.User{
				Username: "TestUser",
				Email:    "TestUser@email.com",
			},
			err: true,
		},
		{
			name: "Empty username and email",
			login: &entities.User{
				Password: "Test$123",
			},
			err: true,
		},
		{
			name: "Username and email used together",
			login: &entities.User{
				Username: "TestUser",
				Email:    "TestUser@email.com",
				Password: "Test$123",
			},
			err: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := ValidateLogin(tt.login)
			if tt.err {
				assert.True(t, len(errMsg) != 0)
			} else {
				assert.True(t, len(errMsg) == 0)
			}
		})
	}
}
