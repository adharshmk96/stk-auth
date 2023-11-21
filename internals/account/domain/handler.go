package domain

import "github.com/adharshmk96/stk/gsk"

// Handler
type AccountHandlers interface {
	// oauth
	LoginWithGoogle(gc *gsk.Context)
	LoginWithGoogleCallback(gc *gsk.Context)

	// account
	AccountDetails(gc *gsk.Context)
}
