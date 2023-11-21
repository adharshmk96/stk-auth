package transport

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

func GenerateOAuthStateCookie() (*http.Cookie, string) {
	expiration := time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration, HttpOnly: true}

	return &cookie, state
}

func GenerateRandomString(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)

	return base64.URLEncoding.EncodeToString(b), err
}

func GenerateSessionCookie(sessionId string) *http.Cookie {

	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := http.Cookie{
		Name:     SESSION_COOKIE_NAME,
		Value:    sessionId,
		Expires:  expiration,
		HttpOnly: true,
		Path:     "/",
	}

	return &cookie

}
