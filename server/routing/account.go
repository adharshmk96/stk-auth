package routing

import "github.com/adharshmk96/stk-auth/internals/account"

func init() {
	RegisterApiRoutes(account.SetupApiRoutes)
	RegisterWebRoutes(account.SetupWebRoutes)
}
