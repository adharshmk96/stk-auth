package services

import (
	"errors"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services/helpers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/golang-jwt/jwt/v5"
)

// GenerateJWT generates a signed JWT token
// - Generates a new JWT token
// - Signs the token with the private key
// ERRORS:
// - service: ErrJWTPrivateKey
func (u *accountService) GenerateJWT(claims *entities.CustomClaims) (string, error) {
	privateKey, err := helpers.GetJWTPrivateKey()
	if err != nil {
		logger.Error("error getting private key: ", err)
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		logger.Error("error signing token: ", err)
		return "", err
	}
	return signedToken, err
}

// ValidateJWT validates the JWT token
// - Retrieves the public key
// - Validates the token
func (u *accountService) ValidateJWT(token string) (*entities.CustomClaims, error) {
	publicKey, err := helpers.GetJWTPublicKey()
	if err != nil {
		logger.Error("error getting public key: ", err)
		return nil, err
	}
	claims := &entities.CustomClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return claims, err
		}
		logger.Error("error verifying token: ", err)
		return claims, svrerr.ErrInvalidToken
	}
	return claims, nil
}
