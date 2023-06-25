package config

import "github.com/adharshmk96/stk/utils"

var ServerMode = utils.GetEnvOrDefault("SERVER_MODE", SERVER_DEV_MODE)
var SessionCookieName = utils.GetEnvOrDefault("SESSION_COOKIE_NAME", DEFAULT_SESSION_COOKIE_NAME)
