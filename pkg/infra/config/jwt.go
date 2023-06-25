package config

import (
	"crypto/rsa"
	"os"

	"github.com/adharshmk96/stk/utils"
	"github.com/golang-jwt/jwt"
)

var JWTPrivateKey = utils.GetEnvOrDefault("JWT_EDCA_PRIVATE_KEY", "")
var JWTPublicKey = utils.GetEnvOrDefault("JWT_EDCA_PUBLIC_KEY", "")

func readPrivateKey() []byte {
	if JWTPrivateKey == "" {
		data, err := os.ReadFile(".keys/private.pem")
		if err != nil {
			JWTPrivateKey = ""
		}
		return data
	}
	return []byte(JWTPrivateKey)
}

func readPublicKey() []byte {
	if JWTPublicKey == "" {
		data, err := os.ReadFile(".keys/private.pem")
		if err != nil {
			JWTPublicKey = ""
		}
		return data
	}
	return []byte(JWTPublicKey)
}

func GetJWTPrivateKey() (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM(readPrivateKey())
}

func GetJWTPublicKey() (*rsa.PublicKey, error) {
	return jwt.ParseRSAPublicKeyFromPEM(readPublicKey())
}
