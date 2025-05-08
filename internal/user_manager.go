package internal

//
//import (
//	"errors"
//	"sync"
//)
//
//// User_auth управляет учетными данными пользователей
//type UserManager struct {
//	users map[string]string // Пример хранения учетных данных в памяти
//	mu    sync.RWMutex      // Мьютекс для безопасного доступа к данным
//}
//
//// New_user_auth создает новый экземпляр User_auth
//func NewUserManager() *UserManager {
//	return &UserManager{
//		users: make(map[string]string),
//	}
//}
//
//// AddUser добавляет нового пользователя
//func (um *UserManager) AddUser(username, password string) error {
//	um.mu.Lock()
//	defer um.mu.Unlock()
//
//	if _, exists := um.users[username]; exists {
//		return errors.New("пользователь уже существует")
//	}
//	um.users[username] = password
//	return nil
//}
//
//// RemoveUser удаляет пользователя
//func (um *UserManager) RemoveUser(username string) error {
//	um.mu.Lock()
//	defer um.mu.Unlock()
//
//	if _, exists := um.users[username]; !exists {
//		return errors.New("пользователь не найден")
//	}
//	delete(um.users, username)
//	return nil
//}
//
//// UpdateUser обновляет учетные данные пользователя
//func (um *UserManager) UpdateUser(username, newPassword string) error {
//	um.mu.Lock()
//	defer um.mu.Unlock()
//
//	if _, exists := um.users[username]; !exists {
//		return errors.New("пользователь не найден")
//	}
//	um.users[username] = newPassword
//	return nil
//}
//
//// ValidateUser проверяет учетные данные пользователя
//func (um *UserManager) ValidateUser(username, password string) bool {
//	um.mu.RLock()
//	defer um.mu.RUnlock()
//
//	storedPassword, exists := um.users[username]
//	return exists && storedPassword == password
//}
