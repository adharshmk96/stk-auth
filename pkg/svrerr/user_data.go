package svrerr

import "errors"

var (
	ErrValidationFailed   = errors.New("failed_data_validation")
	ErrInvalidCredentials = errors.New("error_invalid_credentials")

	ErrParsingQueryParams = errors.New("error_parsing_query_params")

	ErrInvalidSession = errors.New("invalid_session")
	ErrInvalidToken   = errors.New("invalid_token")

	ErrJWTExpired = errors.New("jwt_expired")
)
