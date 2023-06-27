# Sqlite storage repository

[back to main](../../README.md)

This document describes the sqlite storage repository implementation.

## account.go

This file contains the implementation of the AccountStore interface for the sqlite storage repository.

```go
type AccountStore interface {
	SaveUser(user *entities.Account) error
	GetUserByUserID(email string) (*entities.Account, error)
	GetUserByEmail(email string) (*entities.Account, error)
	GetUserByUsername(username string) (*entities.Account, error)
	SaveSession(session *entities.Session) error
	GetSessionByID(sessionID string) (*entities.Session, error)
	GetUserBySessionID(sessionID string) (*entities.Account, error)
	InvalidateSessionByID(sessionID string) error
}
```

**SaveUser** is a method on the sqliteStorage struct. This method is responsible for persisting an Account entity into a SQLite database. It inserts the 
account information into the database using an SQL execution command.

Parameters:
- user: A pointer to an Account entity which contains the details of the  saccount to be saved into the database. The Account entity typically  includes the ID, Username, Password, Salt (for password hasing),  Email, and timestamps for account creation and updates.

Returns:
- If successful, the method returns nil indicating the account information 
  was successfully saved into the database.
- If a 'UNIQUE constraint failed' error occurs (i.e., the username or email 
  already exists in the database), the method returns an svrerr.ErrDBDuplicateEntry error.
- If any other error occurs during the execution of the SQL command or 
  obtaining the number of rows affected, the method returns an 
  svrerr.ErrDBStoringData error.

Usage:

```go
account := &entities.Account{
    ID:        someUUID,
    Username:  "user1",
    Password:  "password1",
    Salt:      "salt1",
    Email:     "user1@example.com",
    CreatedAt: time.Now(),
    UpdatedAt: time.Now(),
}
storage := &sqliteStorage{conn: someDBConn}
err := storage.SaveUser(account)
if err != nil {
    log.Fatal(err)
}
```

Errors:

| Error Type               | Possible Reason                                                                                                                                                                                    | Error                      |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| SQL execution error      | There's a problem executing the SQL statement. This could be due to an issue with the connection to the SQLite database, a syntax error in the SQL statement, or a problem with the provided data. | svrerr.ErrDBStoringData    |
| Rows Affected error      | An issue occurred when trying to obtain the number of rows affected by the SQL statement. This is often related to the SQL connection or a problem with the previously executed SQL statement.     | svrerr.ErrDBStoringData    |
| UNIQUE constraint failed | The provided user data violates a uniqueness constraint. Most likely the username or email already exists in the database.                                                                         | svrerr.ErrDBDuplicateEntry |