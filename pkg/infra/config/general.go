package config

import (
	"github.com/adharshmk96/stk/utils"
)

const (
	SERVER_DEV_MODE             = "dev"
	SERVER_PROD_MODE            = "prod"
	DEFAULT_SESSION_COOKIE_NAME = "session_id"
)

var ServerMode = utils.GetEnvOrDefault("SERVER_MODE", SERVER_DEV_MODE)
var SessionCookieName = utils.GetEnvOrDefault("SESSION_COOKIE_NAME", DEFAULT_SESSION_COOKIE_NAME)
