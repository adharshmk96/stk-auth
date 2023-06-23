package services

import "github.com/adharshmk96/auth-server/pkg/entities"

type userService struct {
	storage entities.UserStore
}

func NewUserService(storage entities.UserStore) entities.UserService {
	return &userService{
		storage: storage,
	}
}

func (u *userService) RegisterUser(user *entities.User) (*entities.User, error) {
	savedUser, err := u.storage.SaveUser(user)
	if err != nil {
		return nil, err
	}
	return savedUser, nil
}

func (u *userService) GetUserByID(id entities.UserID) (*entities.User, error) {
	user, err := u.storage.GetUserByID(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}
