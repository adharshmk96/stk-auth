package services

import (
	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
)

// GetAccountList retrieves the list of accounts from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *authenticationService) GetAccountList(limit int, offset int) ([]*ds.Account, error) {

	if limit == 0 {
		limit = 10
	}

	accounts, err := u.storage.GetAccountList(limit, offset)
	if err != nil {
		return nil, err
	}
	return accounts, nil
}

// GetTotalAccountsCount retrieves the total number of accounts from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *authenticationService) GetTotalAccountsCount() (int64, error) {
	totalAccounts, err := u.storage.GetTotalAccountsCount()
	if err != nil {
		return 0, err
	}
	return totalAccounts, nil
}

// GetAccountDetails retrieves the account details from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *authenticationService) GetAccountDetails(accountID ds.AccountID) (*ds.Account, error) {
	account, err := u.storage.GetAccountByAccountID(accountID.String())
	if err != nil {
		return nil, err
	}
	return account, nil
}
