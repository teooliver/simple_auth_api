package main

import (
	"fmt"
	"net/http"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8000", nil)
}

func register(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if len(username) < 8 || len(password) < 8 {
		err := http.StatusNotAcceptable
		http.Error(w, "Username and password must be at least 8 characters long", err)
		return
	}

	if _, ok := users[username]; ok {
		err := http.StatusConflict
		http.Error(w, "Username already taken", err)
		return
	}

	hashedPassword, _ := hashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}

	fmt.Fprintf(w, "User registered succesfully!\n")

}
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		err := http.StatusNotFound
		http.Error(w, "Invalid username or password", err)
		return
	}

	fmt.Fprintln(w, "Login successful!")

}
func logout(w http.ResponseWriter, r *http.Request)    {}
func protected(w http.ResponseWriter, r *http.Request) {}
