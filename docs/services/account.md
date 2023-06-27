# Account Service

[back to main](../../README.md)

This document describes the Account service implementation.

## account.go

This file contains the Account service implementation.

```go
type AccountService interface {
	RegisterUser(user *entities.Account) (*entities.Account, error)
	LoginUserSession(user *entities.Account) (*entities.Session, error)
	LoginUserSessionToken(user *entities.Account) (string, error)
	GetUserBySessionId(sessionId string) (*entities.Account, error)
	GetUserBySessionToken(sessionToken string) (*entities.AccountWithToken, error)
	LogoutUserBySessionId(sessionId string) error
	LogoutUserBySessionToken(sessionToken string) error
}
```

**RegisterUser** is a method of the accountService struct responsible for
registering a new user in the system. 
It generates a new UUID for the user ID and sets the current timestamp as the creation and update time.
The provided password is hashed using argon2id with a random generated salt.
The method saves the new user details into the storage using the **SaveUser** method.

Parameters:
- user: A pointer to an Account entity. This parameter should contain initial 
  user details such as Username, Password, and Email. Other fields such as ID, 
  CreatedAt, UpdatedAt, Password (hashed version), and Salt are populated 
  within this method.

Returns:
- On success, it returns a pointer to the same Account entity now populated 
  with the additional details (ID, timestamps, hashed password and salt) and nil error.
- If an error occurs at any step of the process, the method returns nil and 
  the error that caused the operation to fail.

Usage:
```go
accountService := &accountService{storage: someStorage}
user := &entities.Account{Username: "username", Password: "password", Email: "email@example.com"}
registeredUser, err := accountService.RegisterUser(user)
if err != nil {
    log.Fatal(err)
}
```

Errors:

| Error Type                               | Possible Reason                                                                                                                           | Error                       |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| Password hashing / salt generation error | An issue occurred while trying to hash the password. This could be due to internal problems with the hashing function.                    | svrerr.ErrHasingPassword    |
| Storage error                            | An issue occurred while trying to save the user into the storage. This error could range from constraint violations to connection issues. | svrerr.DBStoringData        |
| User already exists error                | The provided username or email already exists in the storage.                                                                             | svrerr.ErrUserAlreadyExists |
