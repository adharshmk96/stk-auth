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

func claimExpired(claims *customClaims) bool {
	expiry, err := claims.GetExpirationTime()
	if err != nil {
		return true
	}
	return expiry.Before(time.Now())
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

// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uX2lkIjoiODBmZTVjZjMtNmRhMi00NjUwLWFkOGUtMDQyYWU0ZmI0YzgxIiwidXNlcl9pZCI6ImZmY2IzMzgxLWJiZTUtNGU3Yi04MTMxLTg5M2I1MDU3NmNhOSIsImlzcyI6InN0ay1hdXRoIiwic3ViIjoiYXV0aGVudGljYXRpb24iLCJhdWQiOlsic3RrLWF1dGgiXSwiZXhwIjoxNjg3ODE1MTc4LCJpYXQiOjE2ODc4MTUxNzh9.PXmx6J5fKFVrCPFnAG6MkqZkJ43XWDdUUVl0An_smALfine3UhVj2sO6ooZDivDKsG8yvXpvHTUX85m3B45cGZfiaoSctdaj_DFJkBJN-NQif8rB_HgrjfGantXhClbRINXhujMlcU6ftCV58ItIGM6nYSkK3METCQOv6aQh9Ubpri9yrRtgI6mdSOoDItNGgH7TMUkN5CJMwIjDcmXXzJ3lD0aS7SvmxOCsMTU55mdm-ZQb9yeqqJ-Km6Sxpy309PLtzv-HUoWCppN5wqcOde6OYTApyWgpjbMbiXpb9Zj2qfqGKKb1iFdc-sg98qQ8h734LM2XvxwuA8lgjGu7PA
