package services_test

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

func parseToken(token string) (*entities.CustomClaims, error) {

	claims := entities.CustomClaims{}

	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(viper.GetString(constants.ENV_JWT_EDCA_PUBLIC_KEY)))
	})
	return &claims, err
}
