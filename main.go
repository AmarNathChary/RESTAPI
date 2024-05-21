package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type User struct {
	Username string
	Password string
	UserType string
}

type Book struct {
	Name            string
	Author          string
	PublicationYear int
}

var users = []User{
	{Username: "admin", Password: "admin", UserType: "admin"},
	{Username: "user", Password: "user", UserType: "regular"},
}

var jwtKey = []byte("secret")

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var foundUser User
	for _, u := range users {
		if strings.ToLower(u.Username) == strings.ToLower(user.Username) && u.Password == user.Password {
			foundUser = u
			break
		}
	}

	if foundUser.Username == "" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = foundUser.Username
	claims["userType"] = foundUser.UserType
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{"token": tokenString}
	json.NewEncoder(w).Encode(response)
}

func home(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userType, ok := claims["userType"].(string)
	if !ok {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	
	var books []Book
	var errRead error
	if userType == "admin" {
		books, errRead = readBooks("regularUser.csv", "adminUser.csv")
	} else {
		books, errRead = readBooks("regularUser.csv")
	}
	if errRead != nil {
		http.Error(w, errRead.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(books)
}

func addBook(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userType, ok := claims["userType"].(string)
	if !ok || userType != "admin" {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}

	var book Book
	err = json.NewDecoder(r.Body).Decode(&book)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if book.Name == "" || book.Author == "" || book.PublicationYear == 0 {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	err = writeBook("regularUser.csv", book)
	if err != nil {
		http.Error(w, "Failed to add book", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Book added successfully"})
}

func deleteBook(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userType, ok := claims["userType"].(string)
	if !ok || userType != "admin" {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}

	params := mux.Vars(r)
	Name := params["Name"]

	if Name == "" {
		http.Error(w, "Book Name is required", http.StatusBadRequest)
		return
	}

	err = deleteBookFromCSV("regularUser.csv", Name)
	if err != nil {
		http.Error(w, "Failed to delete book", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Book deleted successfully"})
}

func readBooks(filename string, filenames ...string) ([]Book, error) {
	var books []Book
	for _, file := range append([]string{filename}, filenames...) {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		csvReader := csv.NewReader(f)
		records, err := csvReader.ReadAll()
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			year, err := strconv.Atoi(record[2])
			if err != nil {
				return nil, err
			}
			books = append(books, Book{Name: record[0], Author: record[1], PublicationYear: year})
		}
	}
	return books, nil
}

func writeBook(filename string, book Book) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%s,%s,%d\n", book.Name, book.Author, book.PublicationYear))
	return err
}

func deleteBookFromCSV(filename string, Name string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return err
	}

	var updatedRecords [][]string
	found := false
	for _, record := range records {
		if strings.EqualFold(record[0], Name) {
			found = true
			continue
		}
		updatedRecords = append(updatedRecords, record)
	}

	if !found {
		return fmt.Errorf("Book not found: %s", Name)
	}

	f, err = os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	err = w.WriteAll(updatedRecords)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/home", home).Methods("GET")
	r.HandleFunc("/addBook", addBook).Methods("POST")
	r.HandleFunc("/deleteBook/{Name}", deleteBook).Methods("DELETE")

	log.Fatal(http.ListenAndServe(":3000", r))
}
