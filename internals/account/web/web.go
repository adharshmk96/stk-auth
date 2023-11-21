package web

import (
	"github.com/adharshmk96/stk/gsk"
)

func HomeHandler(gc *gsk.Context) {

	gc.TemplateResponse(&gsk.Tpl{
		TemplatePath: "public/templates/index.html",
		Variables: gsk.Map{
			"Title":   "Account",
			"Content": "Welcome to the account page!",
		},
	})

}
