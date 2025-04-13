# Building a CRUD Web Application with Go and SQLite with authentication

Here's a comprehensive guide to building a web application with Go and SQLite.

## Project Structure

```
go-sqlite-crud/
├── cmd/
│   └── web/
│       ├── main.go
│       └── routes.go
├── internal/
│   ├── auth/
│   ├── handlers/
│   ├── models/
│   ├── repository/
│   └── validation/
├── migrations/
├── static/
├── templates/
├── go.mod
├── go.sum
└── README.md
```

## 1. Setup and Dependencies

### 1.1. Initialize your Go module:

```bash
go mod init github.com/yourusername/go-sqlite-crud
```

### 1.2. Install required dependencies:

```bash
go get github.com/mattn/go-sqlite3
go get golang.org/x/crypto/bcrypt
go get github.com/gorilla/mux
go get github.com/gorilla/sessions
```

## 2. Database Setup (SQLite)

Create a database package in `internal/repository/database.go`:

```go
package repository

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(dbPath string) (*SQLiteRepository, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	return &SQLiteRepository{db: db}, nil
}

func (r *SQLiteRepository) Init() error {
	// Create users table
	_, err := r.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	// Create items table (for your CRUD operations)
	_, err = r.db.Exec(`
		CREATE TABLE IF NOT EXISTS items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			description TEXT,
			user_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create items table: %v", err)
	}

	return nil
}

func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}
```

## 3. User Authentication

### 3.1 User Model (`internal/models/user.go`)

```go
package models

import "time"

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}
```

### 3.2 Authentication Package (`internal/auth/auth.go`)

```go
package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

var (
	store = sessions.NewCookieStore([]byte("your-secret-key"))
	ErrUnauthorized = errors.New("unauthorized")
)

func SetSession(w http.ResponseWriter, r *http.Request, userID int) error {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return err
	}

	session.Values["user_id"] = userID
	session.Values["authenticated"] = true
	session.Options.MaxAge = 86400 // 1 day
	return session.Save(r, w)
}

func ClearSession(w http.ResponseWriter, r *http.Request) error {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return err
	}

	session.Values["authenticated"] = false
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

func IsAuthenticated(r *http.Request) (int, bool) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return 0, false
	}

	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		return 0, false
	}

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		return 0, false
	}

	return userID, true
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
```

### 3.3 User Repository (`internal/repository/user.go`)

```go
package repository

import (
	"database/sql"
	"errors"
	"time"

	"github.com/yourusername/go-sqlite-crud/internal/models"
)

var ErrUserNotFound = errors.New("user not found")

func (r *SQLiteRepository) CreateUser(username, email, password string) (*models.User, error) {
	stmt := `INSERT INTO users (username, email, password) VALUES (?, ?, ?) RETURNING id, created_at`
	
	user := &models.User{
		Username: username,
		Email:    email,
		Password: password,
	}

	err := r.db.QueryRow(stmt, username, email, password).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *SQLiteRepository) GetUserByID(id int) (*models.User, error) {
	user := &models.User{}
	err := r.db.QueryRow("SELECT id, username, email, password, created_at FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt)
	
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *SQLiteRepository) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := r.db.QueryRow("SELECT id, username, email, password, created_at FROM users WHERE email = ?", email).
		Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt)
	
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *SQLiteRepository) UpdateUser(user *models.User) error {
	stmt := `UPDATE users SET username = ?, email = ? WHERE id = ?`
	_, err := r.db.Exec(stmt, user.Username, user.Email, user.ID)
	return err
}

func (r *SQLiteRepository) DeleteUser(id int) error {
	_, err := r.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}
```

### 3.4 Authentication Handlers (`internal/handlers/auth.go`)

```go
package handlers

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/yourusername/go-sqlite-crud/internal/auth"
	"github.com/yourusername/go-sqlite-crud/internal/repository"
)

type AuthHandler struct {
	repo repository.UserRepository
}

func NewAuthHandler(repo repository.UserRepository) *AuthHandler {
	return &AuthHandler{repo: repo}
}

func (h *AuthHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/register", h.handleRegister).Methods("POST")
	r.HandleFunc("/login", h.handleLogin).Methods("POST")
	r.HandleFunc("/logout", h.handleLogout).Methods("POST")
}

func (h *AuthHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Validate input
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if username == "" || email == "" || password == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Create user
	user, err := h.repo.CreateUser(username, email, hashedPassword)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Set session
	err = auth.SetSession(w, r, user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func (h *AuthHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Get form values
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Get user by email
	user, err := h.repo.GetUserByEmail(email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Check password
	if !auth.CheckPasswordHash(password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set session
	err = auth.SetSession(w, r, user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func (h *AuthHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	err := auth.ClearSession(w, r)
	if err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}
```

## 4. CRUD Operations with Pagination and Search

### 4.1 Item Model (`internal/models/item.go`)

```go
package models

import "time"

type Item struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	UserID      int       `json:"user_id"`
	CreatedAt   time.Time `json:"created_at"`
}

type Pagination struct {
	Page      int `json:"page"`
	PerPage   int `json:"per_page"`
	Total     int `json:"total"`
	TotalPages int `json:"total_pages"`
}

type ItemListResponse struct {
	Items      []Item     `json:"items"`
	Pagination Pagination `json:"pagination"`
}
```

### 4.2 Item Repository (`internal/repository/item.go`)

```go
package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/yourusername/go-sqlite-crud/internal/models"
)

var ErrItemNotFound = errors.New("item not found")

func (r *SQLiteRepository) CreateItem(item *models.Item) (*models.Item, error) {
	stmt := `INSERT INTO items (title, description, user_id) VALUES (?, ?, ?) RETURNING id, created_at`
	
	err := r.db.QueryRow(stmt, item.Title, item.Description, item.UserID).
		Scan(&item.ID, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return item, nil
}

func (r *SQLiteRepository) GetItemByID(id int) (*models.Item, error) {
	item := &models.Item{}
	err := r.db.QueryRow("SELECT id, title, description, user_id, created_at FROM items WHERE id = ?", id).
		Scan(&item.ID, &item.Title, &item.Description, &item.UserID, &item.CreatedAt)
	
	if err == sql.ErrNoRows {
		return nil, ErrItemNotFound
	} else if err != nil {
		return nil, err
	}

	return item, nil
}

func (r *SQLiteRepository) UpdateItem(item *models.Item) error {
	stmt := `UPDATE items SET title = ?, description = ? WHERE id = ? AND user_id = ?`
	result, err := r.db.Exec(stmt, item.Title, item.Description, item.ID, item.UserID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrItemNotFound
	}

	return nil
}

func (r *SQLiteRepository) DeleteItem(id, userID int) error {
	result, err := r.db.Exec("DELETE FROM items WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrItemNotFound
	}

	return nil
}

func (r *SQLiteRepository) ListItems(userID int, page, perPage int, search string) (*models.ItemListResponse, error) {
	// Calculate offset
	offset := (page - 1) * perPage

	// Build query
	query := "SELECT id, title, description, user_id, created_at FROM items WHERE user_id = ?"
	countQuery := "SELECT COUNT(*) FROM items WHERE user_id = ?"

	var args []interface{}
	args = append(args, userID)

	if search != "" {
		query += " AND (title LIKE ? OR description LIKE ?)"
		countQuery += " AND (title LIKE ? OR description LIKE ?)"
		searchTerm := "%" + search + "%"
		args = append(args, searchTerm, searchTerm)
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, perPage, offset)

	// Get total count
	var total int
	err := r.db.QueryRow(countQuery, args[:len(args)-2]...).Scan(&total)
	if err != nil {
		return nil, err
	}

	// Calculate total pages
	totalPages := total / perPage
	if total%perPage != 0 {
		totalPages++
	}

	// Get items
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.Item
	for rows.Next() {
		var item models.Item
		err := rows.Scan(&item.ID, &item.Title, &item.Description, &item.UserID, &item.CreatedAt)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	response := &models.ItemListResponse{
		Items: items,
		Pagination: models.Pagination{
			Page:      page,
			PerPage:   perPage,
			Total:     total,
			TotalPages: totalPages,
		},
	}

	return response, nil
}
```

### 4.3 Item Handlers (`internal/handlers/item.go`)

```go
package handlers

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/yourusername/go-sqlite-crud/internal/auth"
	"github.com/yourusername/go-sqlite-crud/internal/models"
	"github.com/yourusername/go-sqlite-crud/internal/repository"
)

type ItemHandler struct {
	repo repository.ItemRepository
}

func NewItemHandler(repo repository.ItemRepository) *ItemHandler {
	return &ItemHandler{repo: repo}
}

func (h *ItemHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/items", h.authMiddleware(h.handleGetItems)).Methods("GET")
	r.HandleFunc("/items", h.authMiddleware(h.handleCreateItem)).Methods("POST")
	r.HandleFunc("/items/{id}", h.authMiddleware(h.handleGetItem)).Methods("GET")
	r.HandleFunc("/items/{id}", h.authMiddleware(h.handleUpdateItem)).Methods("PUT")
	r.HandleFunc("/items/{id}", h.authMiddleware(h.handleDeleteItem)).Methods("DELETE")
}

func (h *ItemHandler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := auth.IsAuthenticated(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add userID to context
		ctx := context.WithValue(r.Context(), "userID", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (h *ItemHandler) handleGetItems(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)

	// Get pagination parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 10
	}

	// Get search query
	search := r.URL.Query().Get("search")

	// Get items
	response, err := h.repo.ListItems(userID, page, perPage, search)
	if err != nil {
		http.Error(w, "Failed to get items", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *ItemHandler) handleCreateItem(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)

	var item models.Item
	err := json.NewDecoder(r.Body).Decode(&item)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if item.Title == "" {
		http.Error(w, "Title is required", http.StatusBadRequest)
		return
	}

	item.UserID = userID
	createdItem, err := h.repo.CreateItem(&item)
	if err != nil {
		http.Error(w, "Failed to create item", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdItem)
}

func (h *ItemHandler) handleGetItem(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	item, err := h.repo.GetItemByID(id)
	if err != nil {
		if err == repository.ErrItemNotFound {
			http.Error(w, "Item not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to get item", http.StatusInternalServerError)
		}
		return
	}

	if item.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func (h *ItemHandler) handleUpdateItem(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	var item models.Item
	err = json.NewDecoder(r.Body).Decode(&item)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if item.Title == "" {
		http.Error(w, "Title is required", http.StatusBadRequest)
		return
	}

	item.ID = id
	item.UserID = userID
	err = h.repo.UpdateItem(&item)
	if err != nil {
		if err == repository.ErrItemNotFound {
			http.Error(w, "Item not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to update item", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func (h *ItemHandler) handleDeleteItem(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	err = h.repo.DeleteItem(id, userID)
	if err != nil {
		if err == repository.ErrItemNotFound {
			http.Error(w, "Item not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to delete item", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

## 5. Input Validation

Create a validation package (`internal/validation/validation.go`):

```go
package validation

import (
	"net/mail"
	"regexp"
)

func ValidateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func ValidatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	
	return hasUpper && hasLower && hasNumber
}

func ValidateUsername(username string) bool {
	if len(username) < 3 || len(username) > 20 {
		return false
	}
	
	return regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username)
}
```

## 6. Main Application Setup (`cmd/web/main.go`)

```go
package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/yourusername/go-sqlite-crud/internal/auth"
	"github.com/yourusername/go-sqlite-crud/internal/handlers"
	"github.com/yourusername/go-sqlite-crud/internal/repository"
)

func main() {
	// Initialize database
	dbRepo, err := repository.NewSQLiteRepository("app.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer dbRepo.Close()

	// Initialize database schema
	err = dbRepo.Init()
	if err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// Create router
	r := mux.NewRouter()

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(dbRepo)
	itemHandler := handlers.NewItemHandler(dbRepo)

	// Register routes
	authHandler.RegisterRoutes(r)
	itemHandler.RegisterRoutes(r)

	// Serve static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Start server
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

## 7. Testing

Create tests for your application. Here's an example test for the item repository (`internal/repository/item_test.go`):

```go
package repository_test

import (
	"testing"
	"time"

	"github.com/yourusername/go-sqlite-crud/internal/models"
	"github.com/yourusername/go-sqlite-crud/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ItemRepositoryTestSuite struct {
	suite.Suite
	repo *repository.SQLiteRepository
}

func (suite *ItemRepositoryTestSuite) SetupTest() {
	repo, err := repository.NewSQLiteRepository(":memory:")
	assert.NoError(suite.T(), err)
	
	err = repo.Init()
	assert.NoError(suite.T(), err)
	
	suite.repo = repo
}

func (suite *ItemRepositoryTestSuite) TearDownTest() {
	suite.repo.Close()
}

func (suite *ItemRepositoryTestSuite) TestCreateAndGetItem() {
	// Create a test user
	user, err := suite.repo.CreateUser("testuser", "test@example.com", "password")
	assert.NoError(suite.T(), err)

	// Create item
	item := &models.Item{
		Title:       "Test Item",
		Description: "Test Description",
		UserID:      user.ID,
	}

	createdItem, err := suite.repo.CreateItem(item)
	assert.NoError(suite.T(), err)
	assert.NotZero(suite.T(), createdItem.ID)
	assert.NotZero(suite.T(), createdItem.CreatedAt)

	// Get item
	retrievedItem, err := suite.repo.GetItemByID(createdItem.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdItem.ID, retrievedItem.ID)
	assert.Equal(suite.T(), "Test Item", retrievedItem.Title)
	assert.Equal(suite.T(), "Test Description", retrievedItem.Description)
	assert.Equal(suite.T(), user.ID, retrievedItem.UserID)
}

func (suite *ItemRepositoryTestSuite) TestUpdateItem() {
	// Create a test user
	user, err := suite.repo.CreateUser("testuser", "test@example.com", "password")
	assert.NoError(suite.T(), err)

	// Create item
	item := &models.Item{
		Title:       "Test Item",
		Description: "Test Description",
		UserID:      user.ID,
	}

	createdItem, err := suite.repo.CreateItem(item)
	assert.NoError(suite.T(), err)

	// Update item
	createdItem.Title = "Updated Title"
	createdItem.Description = "Updated Description"
	err = suite.repo.UpdateItem(createdItem)
	assert.NoError(suite.T(), err)

	// Verify update
	retrievedItem, err := suite.repo.GetItemByID(createdItem.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "Updated Title", retrievedItem.Title)
	assert.Equal(suite.T(), "Updated Description", retrievedItem.Description)
}

func (suite *ItemRepositoryTestSuite) TestDeleteItem() {
	// Create a test user
	user, err := suite.repo.CreateUser("testuser", "test@example.com", "password")
	assert.NoError(suite.T(), err)

	// Create item
	item := &models.Item{
		Title:       "Test Item",
		Description: "Test Description",
		UserID:      user.ID,
	}

	createdItem, err := suite.repo.CreateItem(item)
	assert.NoError(suite.T(), err)

	// Delete item
	err = suite.repo.DeleteItem(createdItem.ID, user.ID)
	assert.NoError(suite.T(), err)

	// Verify deletion
	_, err = suite.repo.GetItemByID(createdItem.ID)
	assert.Equal(suite.T(), repository.ErrItemNotFound, err)
}

func (suite *ItemRepositoryTestSuite) TestListItemsWithPagination() {
	// Create a test user
	user, err := suite.repo.CreateUser("testuser", "test@example.com", "password")
	assert.NoError(suite.T(), err)

	// Create multiple items
	for i := 1; i <= 15; i++ {
		item := &models.Item{
			Title:       fmt.Sprintf("Item %d", i),
			Description: fmt.Sprintf("Description %d", i),
			UserID:      user.ID,
		}
		_, err := suite.repo.CreateItem(item)
		assert.NoError(suite.T(), err)
	}

	// Test pagination
	response, err := suite.repo.ListItems(user.ID, 1, 5, "")
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), response.Items, 5)
	assert.Equal(suite.T(), 15, response.Pagination.Total)
	assert.Equal(suite.T(), 3, response.Pagination.TotalPages)

	// Test second page
	response, err = suite.repo.ListItems(user.ID, 2, 5, "")
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), response.Items, 5)
}

func (suite *ItemRepositoryTestSuite) TestListItemsWithSearch() {
	// Create a test user
	user, err := suite.repo.CreateUser("testuser", "test@example.com", "password")
	assert.NoError(suite.T(), err)

	// Create items with different titles
	titles := []string{"Apple", "Banana", "Orange", "Grape", "Pineapple"}
	for _, title := range titles {
		item := &models.Item{
			Title:       title,
			Description: "Fruit",
			UserID:      user.ID,
		}
		_, err := suite.repo.CreateItem(item)
		assert.NoError(suite.T(), err)
	}

	// Search for "apple"
	response, err := suite.repo.ListItems(user.ID, 1, 10, "apple")
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), response.Items, 2) // Apple and Pineapple
}

func TestItemRepositoryTestSuite(t *testing.T) {
	suite.Run(t, new(ItemRepositoryTestSuite))
}
```

## 8. Running the Application

1. Build and run:
```bash
go run cmd/web/main.go
```

2. The application will be available at `http://localhost:8080`

## 9. API Endpoints

### Authentication
- POST `/register` - Register a new user
- POST `/login` - Login with existing user
- POST `/logout` - Logout current user

### Items CRUD
- GET `/items` - List all items (with pagination and search)
  - Query params: `page`, `per_page`, `search`
- POST `/items` - Create a new item
- GET `/items/{id}` - Get a specific item
- PUT `/items/{id}` - Update an item
- DELETE `/items/{id}` - Delete an item

## Conclusion

This implementation provides a complete CRUD web application with Go and SQLite that includes:

1. User authentication with sessions
2. Input validation for registration and item creation
3. Pagination for listing items
4. Search functionality
5. Comprehensive testing

The application follows a clean architecture with separate layers for handlers, repositories, and models. You can extend it further by adding more features like:

- Email verification
- Password reset
- Role-based access control
- File uploads
- API documentation with Swagger

Remember to:
- Use environment variables for sensitive configuration
- Implement proper error handling and logging
- Add middleware for request logging, CORS, etc.
- Consider using migrations for database schema changes