package config

import (
	"github.com/adharshmk96/stk/utils"
)

const (
	SERVER_DEV_MODE                 = "SERVER_DEV_MODE"
	SERVER_PROD_MODE                = "SERVER_PROD_MODE"
	DEFAULT_SESSION_COOKIE_NAME     = "stk_session"
	DEFAULT_SESSION_JWT_COOKIE_NAME = "stk_session_token"
)

var SERVER_MODE = utils.GetEnvOrDefault("SERVER_MODE", SERVER_DEV_MODE)
var SESSION_COOKIE_NAME = utils.GetEnvOrDefault("SESSION_COOKIE_NAME", DEFAULT_SESSION_COOKIE_NAME)
var JWT_SESSION_COOKIE_NAME = utils.GetEnvOrDefault("JWT_SESSION_COOKIE_NAME", DEFAULT_SESSION_JWT_COOKIE_NAME)
