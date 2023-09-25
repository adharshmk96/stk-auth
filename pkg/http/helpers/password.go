package helpers

import (
	"fmt"
	"net/smtp"
	"net/url"

	"github.com/adharshmk96/stk-auth/server/infra"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/spf13/viper"
)

// email settings
var (
	EmailFrom = viper.GetString(constants.ENV_SERVER_EMAIL_FROM)
	EmailHost = viper.GetString(constants.ENV_SERVER_EMAIL_HOST)
	EmailPort = viper.GetString(constants.ENV_SERVER_EMAIL_PORT)
	EmailUser = viper.GetString(constants.ENV_SERVER_EMAIL_USER)
	EmailPass = viper.GetString(constants.ENV_SERVER_EMAIL_PASS)
	resetURL  = viper.GetString(constants.ENV_SERVER_EMAIL_RESET_URL)
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
