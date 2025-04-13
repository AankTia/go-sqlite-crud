package repository

import (
	"database/sql"
	"errors"

	"githung.com/AankTia/go-sqlite-crud/internal/models"
)

var ErrUserNotFound = errors.New("user nnot found")

func (r *SQLiteRespository) CreateUser(username, email, password string) (*models.User, error) {
	stmt := `INSERT INTO users (username, email, password) VALUES (?,?,?) RETURNING id, created_at`

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

func (r *SQLiteRespository) GetUserByID(id int) (*models.User, error) {
	user := &models.User{}
	err := r.db.QueryRow("SELECT id, username, email, password, created_at FROM users WHERE id = ?", id).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *SQLiteRespository) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := r.db.QueryRow("SELECT id, username, email, password, created_at FROM users WHERE email = ?", email).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *SQLiteRespository) UpdateUser(user *models.User) error {
	stmt := `UPDATE users SET username = ?, email = ? WHERE id = ?`
	_, err := r.db.Exec(stmt, user.Username, user.Email, user.ID)
	return err
}

func (r *SQLiteRespository) DeleteUser(id int) error {
	_, err := r.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}