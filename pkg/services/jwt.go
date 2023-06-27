package services

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type customClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	jwt.RegisteredClaims
}

func NewCustomClaims(userId, sessionId string) jwt.Claims {
	timeNow := time.Now()
	JWT_EXPIRATION_DURATION := time.Hour * 24

	claims := customClaims{
		SessionID: sessionId,
		UserID:    userId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "authentication",
			Issuer:    "stk-auth",
			Audience:  []string{"stk-auth"},
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ExpiresAt: jwt.NewNumericDate(timeNow.Add(JWT_EXPIRATION_DURATION)),
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

func GetSignedToken(privateKey *rsa.PrivateKey, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		logger.Error("error signing token: ", err)
		return "", err
	}
	return signedToken, err
}
