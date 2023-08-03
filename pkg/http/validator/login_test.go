package validator

import (
	"testing"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/stretchr/testify/assert"
)

func TestValidateLogin(t *testing.T) {
	tests := []struct {
		name  string
		login *ds.Account
		err   bool
	}{
		{
			name: "Username and password",
			login: &ds.Account{
				Username: "TestAccount",
				Password: "Test$123",
			},
			err: false,
		},
		{
			name: "Email and password",
			login: &ds.Account{
				Email:    "account@email.com",
				Password: "Test$123",
			},
			err: false,
		},
		{
			name: "Empty password",
			login: &ds.Account{
				Username: "TestAccount",
				Email:    "TestAccount@email.com",
			},
			err: true,
		},
		{
			name: "Empty username and email",
			login: &ds.Account{
				Password: "Test$123",
			},
			err: true,
		},
		{
			name: "Username and email used together",
			login: &ds.Account{
				Username: "TestAccount",
				Email:    "TestAccount@email.com",
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
