package internal

import (
	"errors"
	"fmt"
)

type User struct {
	Username string
	Password string
}

type UserManager struct {
	users map[string]User
}

func NewUserManager() *UserManager {
	return &UserManager{
		users: make(map[string]User),
	}
}

func (um *UserManager) AddUser(username, password string) {
	um.users[username] = User{
		Username: username,
		Password: password,
	}
}

func (um *UserManager) ValidateUser(username, password string) bool {
	user, exists := um.users[username]
	return exists && user.Password == password
}

type AuthManager struct {
	userManager *UserManager
}

func NewAuthManager(um *UserManager) *AuthManager {
	return &AuthManager{
		userManager: um,
	}
}

func (am *AuthManager) Authenticate(username, password string) (*User, error) {
	if am.userManager.ValidateUser(username, password) {
		return &User{Username: username}, nil
	}
	return nil, errors.New("invalid credentials")
}

func (am *AuthManager) CompleteSession(user *User) ([]byte, error) {
	if user == nil {
		return nil, errors.New("nil user")
	}
	return []byte(fmt.Sprintf("SESSION-TOKEN-%s", user.Username)), nil
}
