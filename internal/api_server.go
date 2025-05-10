package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type User_api struct {
	ID       string `json:"id,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

const (
	usersFile     = "users.json"
	jwtSecretKey  = "your-secret-key"
	tokenDuration = 24 * time.Hour
)

var users []User_api

func loadUsers() error {
	file, err := ioutil.ReadFile(usersFile)
	if err != nil {
		if os.IsNotExist(err) {
			users = []User_api{}
			return nil
		}
		return err
	}
	return json.Unmarshal(file, &users)
}

func saveUsers() error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(usersFile, data, 0644)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newUser User_api
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Проверка существования пользователя
	for _, user := range users {
		if user.Username == newUser.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	// Хеширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Password hashing error", http.StatusInternalServerError)
		return
	}

	newUser.Password = string(hashedPassword)
	newUser.ID = generateUniqueID() // Добавьте функцию генерации уникального ID
	users = append(users, newUser)

	if err := saveUsers(); err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginUser User_api
	err := json.NewDecoder(r.Body).Decode(&loginUser)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var foundUser *User_api
	for _, user := range users {
		if user.Username == loginUser.Username {
			foundUser = &user
			break
		}
	}

	if foundUser == nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Проверка пароля
	err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(loginUser.Password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Создание JWT токена
	token, err := createJWTToken(foundUser.Username)
	if err != nil {
		http.Error(w, "Token creation error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
		"token":   token,
	})
}

func createJWTToken(username string) (string, error) {
	expirationTime := time.Now().Add(tokenDuration)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "your-app",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecretKey))
}

func validateJWTToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization token missing", http.StatusUnauthorized)
			return
		}

		claims, err := validateJWTToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Optional: Add username to request context
		ctx := context.WithValue(r.Context(), "username", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func initAPIRoutes() {
	// Загрузка пользователей при старте
	if err := loadUsers(); err != nil {
		panic(err)
	}

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	// Пример защищенного маршрута
	http.HandleFunc("/protected", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Access to protected resource"))
	}))
}

func StartAPIServer() {
	initAPIRoutes()
	port := ":8080"
	fmt.Printf("API Server started on %s\n", port)
	http.ListenAndServe(port, nil)
}

// Вспомогательная функция для генерации уникального ID
func generateUniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
