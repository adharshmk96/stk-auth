package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/adharshmk96/stk-auth/internals/account/api/transport"
	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/internals/account/serr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Inside handler package

var googleOauthConfig *oauth2.Config

func getGoogleOAuthConfig() *oauth2.Config {
	if googleOauthConfig == nil {
		googleOauthConfig = &oauth2.Config{
			RedirectURL:  viper.GetString("oauth.google.redirect_url"),
			ClientID:     viper.GetString("oauth.google.client_id"),
			ClientSecret: viper.GetString("oauth.google.client_secret"),
			Scopes:       viper.GetStringSlice("oauth.google.scopes"),
			Endpoint:     google.Endpoint,
		}
	}
	return googleOauthConfig
}

// Use googleOauthConfig inside your functions as needed.

// GoogleUserInfo represents the user information we receive from Google.
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func (h *accountHandler) LoginWithGoogle(gc *gsk.Context) {
	oauthConfig := getGoogleOAuthConfig()
	cookie, value := transport.GenerateOAuthStateCookie()
	gc.SetCookie(cookie)
	url := oauthConfig.AuthCodeURL(value)
	gc.Status(http.StatusTemporaryRedirect).Redirect(url)
}

func (h *accountHandler) LoginWithGoogleCallback(gc *gsk.Context) {
	oauthConfig := getGoogleOAuthConfig()

	state := gc.Request.FormValue("state")
	oauthState, err := gc.Request.Cookie("oauthstate")
	if err != nil {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": err.Error(),
		})
		return
	}
	if state != oauthState.Value {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": "invalid oauth state",
		})
		return
	}

	code := gc.Request.FormValue("code")
	token, err := oauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": err.Error(),
		})
		return
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v3/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": err.Error(),
		})
		return
	}

	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": err.Error(),
		})
		return
	}

	userData := &GoogleUserInfo{}
	err = json.Unmarshal(contents, userData)

	randomPassword, err := transport.GenerateRandomString(20)
	account := &domain.Account{
		Email:    userData.Email,
		Password: randomPassword,
	}

	// save user data in database with empty password
	err = h.service.CreateAccount(account)
	if err != nil {
		if errors.Is(err, serr.ErrAccountExists) {
			// account already exists, get account from database
			account, err = h.service.GetAccountByEmail(userData.Email)
		} else {
			gc.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
				"message": err.Error(),
			})
			return
		}
	}

	// start session
	session, err := h.service.StartSession(account)
	if err != nil {
		gc.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"message": err.Error(),
		})
		return
	}

	// set session cookie
	cookie := transport.GenerateSessionCookie(session.ID.String())

	gc.SetCookie(cookie)

	gc.Status(http.StatusFound).Redirect(viper.GetString("project.login_success_url"))
}
