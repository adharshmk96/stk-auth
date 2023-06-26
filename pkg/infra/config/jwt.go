package config

import (
	"crypto/rsa"
	"os"

	"github.com/adharshmk96/stk/utils"
	"github.com/golang-jwt/jwt"
)

var (
	JWT_EDCA_PRIVATE_KEY = utils.GetEnvOrDefault("JWT_EDCA_PRIVATE_KEY", "")
	JWT_EDCA_PUBLIC_KEY  = utils.GetEnvOrDefault("JWT_EDCA_PUBLIC_KEY", "")

	JWT_EDCA_PRIVATE_KEY_PATH = utils.GetEnvOrDefault("JWT_EDCA_PRIVATE_KEY_PATH", ".keys/private_key.pem")
	JWT_EDCA_PUBLIC_KEY_PATH  = utils.GetEnvOrDefault("JWT_EDCA_PUBLIC_KEY_PATH", ".keys/public_key.pem")
)

func readPrivateKey() []byte {
	if JWT_EDCA_PRIVATE_KEY == "" {
		data, err := os.ReadFile(JWT_EDCA_PRIVATE_KEY_PATH)
		if err != nil {
			JWT_EDCA_PRIVATE_KEY = ""
		}
		return data
	}
	return []byte(JWT_EDCA_PRIVATE_KEY)
}

func readPublicKey() []byte {
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
	return jwt.ParseRSAPrivateKeyFromPEM(readPrivateKey())
}

func GetJWTPublicKey() (*rsa.PublicKey, error) {
	return jwt.ParseRSAPublicKeyFromPEM(readPublicKey())
}
