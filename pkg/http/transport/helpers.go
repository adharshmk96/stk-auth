package transport

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk/gsk"
	"github.com/spf13/viper"
)

func GetCookieModes() (bool, http.SameSite) {
	secure := viper.GetString(constants.ENV_SERVER_MODE) == constants.SERVER_PROD_MODE
	var sameSite http.SameSite
	if secure {
		sameSite = http.SameSiteLaxMode
	} else {
		sameSite = http.SameSiteLaxMode
	}
	return secure, sameSite

}

func ParseRemoteAddress(remoteAddr string) (ip, port string) {
	ip = remoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
		port = remoteAddr[colonIndex+1:]
	}
	return ip, port
}

func GetSessionOrTokenFromCookie(ctx gsk.Context) (*http.Cookie, *http.Cookie, error) {
	sessionCookie, scerr := ctx.GetCookie(viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
	sessionToken, sterr := ctx.GetCookie(viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
	if (scerr != nil && sterr != nil) || (scerr == nil && sessionCookie.Value == "") || (sterr == nil && sessionToken.Value == "") {
		return nil, nil, svrerr.ErrInvalidCredentials
	}
	return sessionCookie, sessionToken, nil
}

func ParseLimitAndOffset(limit string, offset string) (limitInt int, offsetInt int, err error) {
	if limit != "" {
		limitInt, err = strconv.Atoi(limit)
		if err != nil {
			return 0, 0, svrerr.ErrParsingQueryParams
		}
	}
	if offset != "" {
		offsetInt, err = strconv.Atoi(offset)
		if err != nil {
			return 0, 0, svrerr.ErrParsingQueryParams
		}
	}
	return limitInt, offsetInt, nil
}
