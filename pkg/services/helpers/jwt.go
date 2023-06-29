package helpers

import (
	"crypto/rsa"
	"os"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/golang-jwt/jwt/v5"
)

var logger = infra.GetLogger()

var config = infra.GetConfig()

type customClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	jwt.RegisteredClaims
}

func GetSignedTokenWithClaims(claims jwt.Claims) (string, error) {

	private_key, err := GetJWTPrivateKey()
	if err != nil {
		logger.Error("error getting private key: ", err)
		return "", err
	}
	signedToken, err := getSignedToken(private_key, claims)
	if err != nil {
		logger.Error("error generating token: ", err)
		return "", err
	}
	return signedToken, err
}

func VerifyToken(token string) (*customClaims, error) {
	publicKey, err := GetJWTPublicKey()
	if err != nil {
		logger.Error("error getting public key: ", err)
		return nil, err
	}
	claims, err := verifyToken(publicKey, token)
	if err != nil {
		logger.Error("error verifying token: ", err)
		return claims, err
	}
	return claims, nil
}

func MakeCustomClaims(userId, sessionId string) jwt.Claims {
	timeNow := time.Now()

	claims := customClaims{
		SessionID: sessionId,
		UserID:    userId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId,
			Issuer:    config.JWT_ISSUER,
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ExpiresAt: jwt.NewNumericDate(timeNow.Add(config.JWT_EXPIRATION_DURATION)),
		},
	}

	return claims
}

func verifyToken(publicKey *rsa.PublicKey, token string) (*customClaims, error) {
	claims := &customClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return claims, err
	}
	return claims, nil
}

func getSignedToken(privateKey *rsa.PrivateKey, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		logger.Error("error signing token: ", err)
		return "", err
	}
	return signedToken, err
}

/*
ReadPrivateKey reads the private key from the environment variable or the file and returns as byte array
*/
func ReadPrivateKey() []byte {
	JWT_EDCA_PRIVATE_KEY := config.JWT_EDCA_PRIVATE_KEY
	JWT_EDCA_PRIVATE_KEY_PATH := config.JWT_EDCA_PRIVATE_KEY_PATH
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
	JWT_EDCA_PUBLIC_KEY := config.JWT_EDCA_PUBLIC_KEY
	JWT_EDCA_PUBLIC_KEY_PATH := config.JWT_EDCA_PUBLIC_KEY_PATH
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
