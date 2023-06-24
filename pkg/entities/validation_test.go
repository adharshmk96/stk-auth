package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateUser(t *testing.T) {
	tests := []struct {
		name     string
		user     *Account
		expected map[string]string
	}{
		{
			name: "Valid user",
			user: &Account{
				Username: "TestUser",
				Email:    "testuser@example.com",
				Password: "Test$123",
			},
			expected: map[string]string{},
		},
		{
			name: "Empty username and email",
			user: &Account{
				Password: "Test$123",
			},
			expected: map[string]string{
				"username": EmailOrUsernameRequired,
				"email":    EmailOrUsernameRequired,
			},
		},
		{
			name: "Invalid email",
			user: &Account{
				Username: "TestUser",
				Email:    "invalid",
				Password: "Test$123",
			},
			expected: map[string]string{
				"email": EmailMustBeValid,
			},
		},
		// Add more cases as needed.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidateUser(tt.user)

			if len(errors) != len(tt.expected) {
				t.Errorf("expected %d error(s), got %d: %v", len(tt.expected), len(errors), errors)
				return
			}

			for field, expectedError := range tt.expected {
				if actualError, ok := errors[field]; !ok || actualError != expectedError {
					t.Errorf("expected error for field %q to be %q, got %q", field, expectedError, actualError)
				}
			}
		})
	}
}

func TestValidationFuncitons(t *testing.T) {
	t.Run("email validation function", func(t *testing.T) {
		tests := []struct {
			name  string
			email string
			err   bool
		}{
			{
				name:  "Valid email",
				email: "user@email.com",
				err:   false,
			},
			{
				name:  "Invalid email",
				email: "invalid",
				err:   true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validateEmail(tt.email)
				if tt.err {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("password validation function", func(t *testing.T) {
		tests := []struct {
			name     string
			password string
			err      bool
		}{
			{
				name:     "Valid password",
				password: "Test$123",
				err:      false,
			},
			{
				name:     "Invalid password",
				password: "invalid",
				err:      true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validatePassword(tt.password)
				if tt.err {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("username validation function", func(t *testing.T) {
		tests := []struct {
			name     string
			username string
			err      bool
		}{
			{
				name:     "Valid username",
				username: "TestUser",
				err:      false,
			},
			{
				name:     "Invalid username",
				username: "in",
				err:      true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validateUsername(tt.username)
				if tt.err {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}
