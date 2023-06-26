package config

import (
	"crypto/rsa"
	"os"

	"github.com/adharshmk96/stk/utils"
	"github.com/golang-jwt/jwt"
)

const (
	PRIVATE_KEY_PATH = ".keys/private_key.pem"
	PUBLIC_KEY_PATH  = ".keys/public_key.pem"
)

var JWTPrivateKey = utils.GetEnvOrDefault("JWT_EDCA_PRIVATE_KEY", "")
var JWTPublicKey = utils.GetEnvOrDefault("JWT_EDCA_PUBLIC_KEY", "")

func readPrivateKey() []byte {
	if JWTPrivateKey == "" {
		data, err := os.ReadFile(PRIVATE_KEY_PATH)
		if err != nil {
			JWTPrivateKey = ""
		}
		return data
	}
	return []byte(JWTPrivateKey)
}

func readPublicKey() []byte {
	if JWTPublicKey == "" {
		data, err := os.ReadFile(PUBLIC_KEY_PATH)
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
