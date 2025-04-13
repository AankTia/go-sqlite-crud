package auth

import (
	"errors"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var (
	store           = sessions.NewCookieStore([]byte("your-secret-key"))
	ErrUnauthorized = errors.New("unauthorized")
)

func SetSession(w http.ResponseWriter, r *http.Request, userID int) error {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return err
	}

	session.Values["user_id"] = userID
	session.Values["authenticated"] = true
	session.Options.MaxAge = 86400 // 1day

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

	UserID, ok := session.Values["user_id"].(int)
	if !ok {
		return 0, false
	}

	return UserID, true
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
