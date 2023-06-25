package config

import (
	"crypto/rsa"
	"os"

	"github.com/adharshmk96/stk/utils"
	"github.com/golang-jwt/jwt"
)

var JWTPrivateKey = utils.GetEnvOrDefault("JWT_EDCA_PRIVATE_KEY", "jwt_rs256_private_key")
var JWTPublicKey = utils.GetEnvOrDefault("JWT_EDCA_PUBLIC_KEY", "jwt_rs256_public_key")

func readJWTKeys() {
	if JWTPrivateKey == "" {
		data, err := os.ReadFile(".keys/private.pem")
		if err != nil {
			JWTPrivateKey = ""
		}
		JWTPrivateKey = string(data)
	}
	if JWTPublicKey == "" {
		data, err := os.ReadFile(".keys/private.pem")
		if err != nil {
			JWTPublicKey = ""
		}
		JWTPublicKey = string(data)
	}
}

func GetJWTPrivateKey() (*rsa.PrivateKey, error) {
	readJWTKeys()
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTPrivateKey))
}

func GetJWTPublicKey() (*rsa.PublicKey, error) {
	readJWTKeys()
	return jwt.ParseRSAPublicKeyFromPEM([]byte(JWTPublicKey))
}
