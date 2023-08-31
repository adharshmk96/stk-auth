package handlers

import (
	"net/http"
	"path"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk/gsk"
	"github.com/spf13/viper"
)

// update these with your own values
var (
	domain            = viper.GetString(constants.ENV_SERVER_DOMAIN)
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  path.Join("https://", domain, "oauth/google/callback"),
		ClientID:     "your-google-client-id",     // replace with your ClientID
		ClientSecret: "your-google-client-secret", // replace with your ClientSecret
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
	// random string for oauth2 API calls to protect against CSRF
	oauthStateString = "random-string"
)

func (h *oauthHandler) GoogleOauthLogin(gc *gsk.Context) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	gc.Redirect(url)
}

type oauthData struct {
	state string
	code  string
}

func (h *oauthHandler) GoogleOauthCallback(gc *gsk.Context) {
	var data oauthData

	data.code = gc.Request.FormValue("code")
	data.state = gc.Request.FormValue("state")

	if data.state != oauthStateString {
		gc.Status(http.StatusUnauthorized).JSONResponse("invalid oauth state")
		return
	}

	token, err := googleOauthConfig.Exchange(oauth2.NoContext, data.code)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(err.Error())
		return
	}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(err.Error())
		return
	}
	defer resp.Body.Close()

	// TODO: save account details to database
	// TODO: create session and return session token

	gc.Status(http.StatusOK).JSONResponse("login successful")
}
