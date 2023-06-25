package validator

import (
	"testing"

	"github.com/adharshmk96/auth-server/pkg/entities"
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
			err := ValidateLogin(tt.login)
			if tt.err {
				if err == nil {
					t.Errorf("ValidateLogin() error = %v, wantErr %v", err, tt.err)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateLogin() error = %v, wantErr %v", err, tt.err)
				}
			}
		})
	}
}
