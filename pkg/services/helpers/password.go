package helpers

import "fmt"

func SendPasswordResetEmail(email string, resetToken string) error {
	fmt.Println("Sending password reset email to: ", email)
	return nil
}
