package services

import "github.com/adharshmk96/stk-auth/pkg/entities"

// GetUserList retrieves the list of users from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *adminService) GetUserList(limit int, offset int) ([]*entities.User, error) {

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
func (u *adminService) GetTotalUsersCount() (int64, error) {
	totalUsers, err := u.storage.GetTotalUsersCount()
	if err != nil {
		return 0, err
	}
	return totalUsers, nil
}

// GetUserDetails retrieves the user details from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *adminService) GetUserDetails(userID entities.UserID) (*entities.User, error) {
	user, err := u.storage.GetUserByUserID(userID.String())
	if err != nil {
		return nil, err
	}
	return user, nil
}
