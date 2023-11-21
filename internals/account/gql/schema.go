package gql

import (
	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/graphql-go/graphql"
)

var accounts []domain.Account
var sessions []domain.Session

var accountType = graphql.NewObject(
	graphql.ObjectConfig{
		Name: "Account",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.String,
			},
			"first_name": &graphql.Field{
				Type: graphql.String,
			},
			"last_name": &graphql.Field{
				Type: graphql.String,
			},
			"username": &graphql.Field{
				Type: graphql.String,
			},
			"email": &graphql.Field{
				Type: graphql.String,
			},
			"password": &graphql.Field{
				Type: graphql.String,
			},
			"salt": &graphql.Field{
				Type: graphql.String,
			},
			"created_at": &graphql.Field{
				Type: graphql.DateTime,
			},
			"updated_at": &graphql.Field{
				Type: graphql.DateTime,
			},
		},
	},
)

var sessionType = graphql.NewObject(
	graphql.ObjectConfig{
		Name: "Session",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.String,
			},
			"account_id": &graphql.Field{
				Type: graphql.String,
			},
			"active": &graphql.Field{
				Type: graphql.Boolean,
			},
			"created_at": &graphql.Field{
				Type: graphql.DateTime,
			},
		},
	},
)

func accountFields() *graphql.Field {
	return &graphql.Field{
		Type:        accountType,
		Description: "Get account by id",
		Args: graphql.FieldConfigArgument{
			"id": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
		},
		Resolve: accountResolver,
		Name:    "account",
	}
}

func sessionField() *graphql.Field {
	return &graphql.Field{
		Type:        sessionType,
		Description: "Get session by id",
		Args: graphql.FieldConfigArgument{
			"id": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
		},
		Resolve: sessionResolver,
		Name:    "session",
	}
}
