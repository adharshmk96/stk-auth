package services

import "github.com/adharshmk96/stk-auth/pkg/entities"

// GetUserList retrieves the list of users from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *authenticationService) GetUserList(limit int, offset int) ([]*entities.User, error) {

	if limit == 0 {
		limit = 10
	}

	users, err := u.storage.GetUserList(limit, offset)
	if err != nil {
		return nil, err
	}
	return users, nil
}

// GetTotalUsersCount retrieves the total number of users from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *authenticationService) GetTotalUsersCount() (int64, error) {
	totalUsers, err := u.storage.GetTotalUsersCount()
	if err != nil {
		return 0, err
	}
	return totalUsers, nil
}
