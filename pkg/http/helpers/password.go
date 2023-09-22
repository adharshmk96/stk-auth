package helpers

import (
	"fmt"
	"net/smtp"
	"net/url"

	"github.com/adharshmk96/stk-auth/server/infra"
	"github.com/spf13/viper"
)

// email settings
var (
	EmailFrom = viper.GetString("email.from")
	EmailHost = viper.GetString("email.host")
	EmailPort = viper.GetString("email.port")
	EmailUser = viper.GetString("email.user")
	EmailPass = viper.GetString("email.pass")

	resetURL = viper.GetString("email.reset_url")
)

func SendPasswordResetEmail(email string, resetToken string) error {
	logger := infra.GetLogger()
	logger.Info("Sending password reset email to: " + email)
	u, err := url.Parse(resetURL)
	if err != nil {
		logger.Error("error parsing url: ", err)
	}

	q := u.Query()
	q.Set("token", resetToken)
	u.RawQuery = q.Encode()

	emailBody := fmt.Sprintf("Click the link below to reset your password:\n\n%s", u.String())

	err = smtp.SendMail(
		EmailHost+":"+EmailPort,
		smtp.PlainAuth("", EmailUser, EmailPass, EmailHost),
		EmailFrom,
		[]string{email},
		[]byte(emailBody),
	)
	if err != nil {
		logger.Error("error sending password reset email: ", err)
		return err
	}

	return nil
}
