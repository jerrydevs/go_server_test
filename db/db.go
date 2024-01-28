package db

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorID int    `json:"author_id"`
}

type User struct {
	Id          int    `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

type UserResponse struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps      map[int]Chirp   `json:"chirps"`
	Users       map[string]User `json:"users"`
	NextChirpId int             `json:"nextChirpId"`
	NextUserId  int             `json:"nextUserId"`
}

func NewDB(path string) (*DB, error) {
	db := &DB{}
	db.path = path
	db.mux = &sync.RWMutex{}
	err := db.ensureDB()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func DeleteDB(path string) error {
	return os.Remove(path)
}

func (db *DB) CreateUser(email, hashedPassword string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	if _, ok := dbStructure.Users[email]; ok {
		return User{}, errors.New("user already exists")
	}

	nextId := dbStructure.NextUserId
	newUser := User{
		Id:          nextId,
		Email:       email,
		Password:    hashedPassword,
		IsChirpyRed: false,
	}
	dbStructure.NextUserId = nextId + 1

	dbStructure.Users[email] = newUser
	_, err = json.Marshal(dbStructure)
	if err != nil {
		return User{}, err
	}

	err = db.writeDB(*dbStructure)
	if err != nil {
		return User{}, err
	}

	return newUser, nil
}

func (db *DB) UpgradeUser(userId int) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	var foundUser *User = nil
	for _, user := range dbStructure.Users {
		if user.Id == userId {
			foundUser = &user
			break
		}
	}

	if foundUser == nil {
		return errors.New("user not found")
	}

	dbStructure.Users[foundUser.Email] = User{
		Id:          foundUser.Id,
		Email:       foundUser.Email,
		Password:    foundUser.Password,
		IsChirpyRed: true,
	}

	_, err = json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	err = db.writeDB(*dbStructure)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) UpdateUser(userId int, email, hashedPassword string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	var foundUser *User = nil
	for _, user := range dbStructure.Users {
		if user.Id == userId {
			foundUser = &user
			break
		}
	}

	if foundUser == nil {
		return User{}, errors.New("user not found")
	}

	newUser := User{
		Id:       foundUser.Id,
		Email:    email,
		Password: hashedPassword,
	}

	dbStructure.Users[email] = newUser
	_, err = json.Marshal(dbStructure)
	if err != nil {
		return User{}, err
	}

	err = db.writeDB(*dbStructure)
	if err != nil {
		return User{}, err
	}

	return newUser, nil
}

func (db *DB) GetUser(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	if user, ok := dbStructure.Users[email]; !ok {
		return User{}, errors.New("user not found")
	} else {
		return user, nil
	}
}

func (db *DB) GetUserByID(userId int) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Id == userId {
			return user, nil
		}
	}

	return User{}, errors.New("user not found")
}

func (db *DB) CreateChirp(body string, authorID int) (Chirp, error) {
	dbStructure, err := db.loadDB()

	if err != nil {
		return Chirp{}, err
	}

	nextId := dbStructure.NextChirpId
	newChirp := Chirp{
		Id:       nextId,
		Body:     body,
		AuthorID: authorID,
	}
	dbStructure.Chirps[nextId] = newChirp
	dbStructure.NextChirpId = nextId + 1

	_, err = json.Marshal(dbStructure)
	if err != nil {
		return Chirp{}, err
	}

	err = db.writeDB(*dbStructure)
	if err != nil {
		return Chirp{}, err
	}

	return newChirp, nil
}

func (db *DB) DeleteChirp(chirpId int, authorId int) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	chirp, ok := dbStructure.Chirps[chirpId]
	if !ok {
		return errors.New("chirp not found")
	}

	if chirp.AuthorID != authorId {
		return errors.New("chirp not found")
	}

	delete(dbStructure.Chirps, chirpId)
	return nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	chirps := []Chirp{}
	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps, nil
}

func (db *DB) GetChirp(chirpId int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	chirp, ok := dbStructure.Chirps[chirpId]
	if !ok {
		return Chirp{}, errors.New("chirp not found")
	}

	return chirp, nil
}

func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); err == nil {
		return nil
	} else {
		emptyJson := []byte("{\"chirps\":{},\"users\":{},\"nextChirpId\":1,\"nextUserId\":1}")
		err = os.WriteFile(db.path, emptyJson, 0644)
		if err != nil {
			return err
		}
		return nil
	}
}

func (db *DB) loadDB() (*DBStructure, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	data, err := os.ReadFile(db.path)
	if err != nil {
		return nil, err
	}

	dbStructure := DBStructure{}
	err = json.Unmarshal(data, &dbStructure)
	if err != nil {
		return nil, err
	}

	return &dbStructure, nil
}

func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	data, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
