package config

import (
	"github.com/adharshmk96/stk/utils"
)

const (
	SERVER_DEV_MODE             = "SERVER_DEV_MODE"
	SERVER_PROD_MODE            = "SERVER_PROD_MODE"
	DEFAULT_SESSION_COOKIE_NAME = "session_id"
)

var SERVER_MODE = utils.GetEnvOrDefault("SERVER_MODE", SERVER_DEV_MODE)
var SESSION_COOKIE_NAME = utils.GetEnvOrDefault("SESSION_COOKIE_NAME", DEFAULT_SESSION_COOKIE_NAME)
