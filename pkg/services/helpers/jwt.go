package helpers

import (
	"crypto/rsa"
	"os"

	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

/*
ReadPrivateKey reads the private key from the environment variable or the file and returns as byte array
*/
func ReadPrivateKey() []byte {
	JWT_EDCA_PRIVATE_KEY := viper.GetString(constants.ENV_JWT_EDCA_PRIVATE_KEY)
	JWT_EDCA_PRIVATE_KEY_PATH := viper.GetString(constants.ENV_JWT_EDCA_PRIVATE_KEY_PATH)
	if JWT_EDCA_PRIVATE_KEY == "" {
		data, err := os.ReadFile(JWT_EDCA_PRIVATE_KEY_PATH)
		if err != nil {
			JWT_EDCA_PRIVATE_KEY = ""
		}
		return data
	}
	return []byte(JWT_EDCA_PRIVATE_KEY)
}

/*
ReadPublicKey reads the public key from the environment variable or the file and returns as byte array
*/
func ReadPublicKey() []byte {
	JWT_EDCA_PUBLIC_KEY := viper.GetString(constants.ENV_JWT_EDCA_PUBLIC_KEY)
	JWT_EDCA_PUBLIC_KEY_PATH := viper.GetString(constants.ENV_JWT_EDCA_PUBLIC_KEY_PATH)
	if JWT_EDCA_PUBLIC_KEY == "" {
		data, err := os.ReadFile(JWT_EDCA_PUBLIC_KEY_PATH)
		if err != nil {
			JWT_EDCA_PUBLIC_KEY = ""
		}
		return data
	}
	return []byte(JWT_EDCA_PUBLIC_KEY)
}

func GetJWTPrivateKey() (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM(ReadPrivateKey())
}

func GetJWTPublicKey() (*rsa.PublicKey, error) {
	return jwt.ParseRSAPublicKeyFromPEM(ReadPublicKey())
}
