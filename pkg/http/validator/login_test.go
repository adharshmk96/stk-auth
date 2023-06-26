package validator

import (
	"testing"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/stretchr/testify/assert"
)

func TestValidateLogin(t *testing.T) {
	tests := []struct {
		name  string
		login *entities.Account
		err   bool
	}{
		{
			name: "Login with username",
			login: &entities.Account{
				Username: "TestUser",
				Password: "Test$123",
			},
			err: false,
		},
		{
			name: "Login with email",
			login: &entities.Account{
				Email:    "user@email.com",
				Password: "Test$123",
			},
			err: false,
		},
		{
			name: "Empty password",
			login: &entities.Account{
				Username: "TestUser",
				Email:    "TestUser@email.com",
			},
			err: true,
		},
		{
			name: "Empty username and email",
			login: &entities.Account{
				Password: "Test$123",
			},
			err: true,
		},
		{
			name: "username and email used together",
			login: &entities.Account{
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
