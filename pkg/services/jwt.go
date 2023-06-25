package services

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type CustomClaims struct {
	sessionID string
	userID    string
	jwt.StandardClaims
}

func getClaims(sessionId, userId string) jwt.Claims {
	claims := CustomClaims{
		sessionID: sessionId,
		userID:    userId,
		StandardClaims: jwt.StandardClaims{
			Subject:   "authentication",
			Issuer:    "auth-server",
			Audience:  "auth-server",
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	return claims
}
