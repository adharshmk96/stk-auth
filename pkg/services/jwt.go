package services

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type CustomClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	jwt.StandardClaims
}

func getClaims(sessionId, userId string) jwt.Claims {
	claims := CustomClaims{
		SessionID: sessionId,
		UserID:    userId,
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
