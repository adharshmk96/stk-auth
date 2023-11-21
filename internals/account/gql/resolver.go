package gql

import "github.com/graphql-go/graphql"

var accountResolver graphql.FieldResolveFn = func(p graphql.ResolveParams) (interface{}, error) {
	id, ok := p.Args["id"].(string)
	if ok {
		for _, account := range accounts {
			if account.ID.String() == id {
				return account, nil
			}
		}
	}

	return nil, nil
}

var sessionResolver graphql.FieldResolveFn = func(p graphql.ResolveParams) (interface{}, error) {
	id, ok := p.Args["id"].(string)
	if ok {
		for _, session := range sessions {
			if session.ID.String() == id {
				return session, nil
			}
		}
	}

	return nil, nil
}
