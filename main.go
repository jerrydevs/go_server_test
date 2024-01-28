package main

import (
	"chirps/db"
	"chirps/handlers"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type State struct {
	Hits          int
	DB            *db.DB
	JWTSecret     string
	RevokedTokens map[string]time.Time
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *State) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Hits++
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func (s *State) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
	<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
	</html>
	`, s.Hits)))
}

func decodeParams(r *http.Request, params interface{}) error {
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(params)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		return err
	}
	return nil
}

func (s *State) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	chirps, err := s.DB.GetChirps()
	if err != nil {
		log.Printf("Error getting chirps: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(chirps)
	if err != nil {
		log.Printf("Error marshalling chirps: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func getProfanities() []string {
	return []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}
}

func (s *State) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	chirpId := chi.URLParam(r, "chirpId")
	chirpIdInt, err := strconv.Atoi(chirpId)
	if err != nil {
		log.Printf("Error parsing chirpId: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	chirp, err := s.DB.GetChirp(chirpIdInt)
	if fmt.Sprint(err) == "chirp not found" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("Error getting chirp: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(chirp)
	if err != nil {
		log.Printf("Error marshalling chirp: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *State) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.JWTSecret), nil
	})
	if err != nil {
		log.Printf("Error parsing token: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		handlers.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	profanities := getProfanities()
	profanitiesSet := make(map[string]struct{})
	for _, profanity := range profanities {
		profanitiesSet[profanity] = struct{}{}
	}

	chirpTokens := strings.Split(params.Body, " ")
	for idx, token := range chirpTokens {
		if _, ok := profanitiesSet[strings.ToLower(token)]; ok {
			chirpTokens[idx] = "****"
		}
	}

	tokenSubject, err := token.Claims.GetSubject()
	if err != nil {
		log.Printf("Error getting subject: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	authorIDInt, err := strconv.Atoi(tokenSubject)
	if err != nil {
		log.Printf("Error parsing authorID: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	chirp, err := s.DB.CreateChirp(strings.Join(chirpTokens, " "), authorIDInt)
	if err != nil {
		log.Printf("Error creating chirp: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	handlers.RespondWithJSON(w, http.StatusCreated, chirp)
}

func (s *State) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.JWTSecret), nil
	})
	if err != nil {
		log.Printf("Error parsing token: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	tokenSubject, err := token.Claims.GetSubject()
	if err != nil {
		log.Printf("Error getting subject: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	authorIDInt, err := strconv.Atoi(tokenSubject)
	if err != nil {
		log.Printf("Error parsing authorID: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	chirpId := chi.URLParam(r, "chirpID")
	chirpIDInt, err := strconv.Atoi(chirpId)
	if err != nil {
		log.Printf("Error parsing chirpId: %s", err)
		handlers.RespondWithError(w, http.StatusBadRequest, "Invalid chirpId")
		return
	}

	chirp, err := s.DB.GetChirp(chirpIDInt)
	if err != nil {
		log.Printf("Error getting chirp: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	if chirp.AuthorID != authorIDInt {
		handlers.RespondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	err = s.DB.DeleteChirp(chirpIDInt, authorIDInt)
	if err != nil {
		log.Printf("Error deleting chirp: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *State) createUserHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	params := parameters{}
	err := decodeParams(r, &params)
	if err != nil {
		handlers.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := s.DB.CreateUser(params.Email, string(hashedPassword))
	if err != nil {
		log.Printf("Error creating user: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	if err == ErrUserAlreadyExists {
		handlers.RespondWithError(w, http.StatusConflict, "User already exists")
		return
	}

	res := struct {
		Email       string `json:"email"`
		Id          int    `json:"id"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}{
		Email:       user.Email,
		Id:          user.Id,
		IsChirpyRed: user.IsChirpyRed,
	}

	handlers.RespondWithJSON(w, http.StatusCreated, res)
}

func (s *State) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.JWTSecret), nil
	})
	if err != nil {
		log.Printf("Error parsing token: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}
	tokenIssuer, err := token.Claims.GetIssuer()
	if err != nil {
		log.Printf("Error getting issuer: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}
	if tokenIssuer != "chirpy-access" {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	log.Printf("%+v\n", token.Claims)
	log.Printf("%+v\n", token.Claims.(*jwt.RegisteredClaims).Subject)

	userIdInt, err := strconv.Atoi(token.Claims.(*jwt.RegisteredClaims).Subject)
	if err != nil {
		log.Printf("Error parsing userId: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	currUser, err := s.DB.GetUserByID(userIdInt)
	if err != nil {
		log.Printf("Error getting user: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	params := parameters{}
	err = decodeParams(r, &params)
	if err != nil {
		handlers.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := s.DB.UpdateUser(currUser.Id, params.Email, string(hashedPassword))
	if err != nil {
		log.Printf("Error updating user: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	res := struct {
		Email       string `json:"email"`
		Id          int    `json:"id"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}{
		Email:       user.Email,
		Id:          user.Id,
		IsChirpyRed: user.IsChirpyRed,
	}

	handlers.RespondWithJSON(w, http.StatusOK, res)
}

func (s *State) loginHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Expires  int    `json:"expires_in_seconds"`
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		handlers.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := s.DB.GetUser(params.Email)
	if err != nil {
		log.Printf("Error getting user: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	if err == ErrUserNotFound {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(params.Password))
	if err != nil {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	accessClaims := &jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   strconv.Itoa(user.Id),
	}

	refreshClaims := &jwt.RegisteredClaims{
		Issuer:    "chirpy-refresh",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().AddDate(0, 0, 60)),
		Subject:   strconv.Itoa(user.Id),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString([]byte(s.JWTSecret))
	if err != nil {
		log.Printf("Error signing token: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(s.JWTSecret))
	if err != nil {
		log.Printf("Error signing token: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	res := struct {
		Email        string `json:"email"`
		Id           int    `json:"id"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}{
		Email:        user.Email,
		Id:           user.Id,
		IsChirpyRed:  user.IsChirpyRed,
		Token:        signedAccessToken,
		RefreshToken: signedRefreshToken,
	}

	handlers.RespondWithJSON(w, http.StatusOK, res)
}

func (s *State) refreshHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.JWTSecret), nil
	})
	if err != nil {
		log.Printf("Error parsing token: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}
	tokenIssuer, err := token.Claims.GetIssuer()
	if err != nil {
		log.Printf("Error getting issuer: %s", err)
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}
	if tokenIssuer != "chirpy-refresh" {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}
	if _, ok := s.RevokedTokens[tokenString]; ok {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	accessClaims := &jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   token.Claims.(*jwt.RegisteredClaims).Subject,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString([]byte(s.JWTSecret))
	if err != nil {
		log.Printf("Error signing token: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	res := struct {
		Token string `json:"token"`
	}{
		Token: signedAccessToken,
	}

	handlers.RespondWithJSON(w, http.StatusOK, res)
}

func (s *State) revokeHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		handlers.RespondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	s.RevokedTokens[tokenString] = time.Now()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *State) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	apiKeyString := strings.TrimPrefix(authHeader, "ApiKey ")
	if apiKeyString != os.Getenv("POLKA_API_KEY") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID int `json:"user_id"`
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		handlers.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusOK)
	}

	fmt.Printf("%d", params.Data.UserID)

	user, err := s.DB.GetUserByID(params.Data.UserID)
	if fmt.Sprint(err) == "user not found" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("Error getting user: %s", err)
		handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if params.Event == "user.upgraded" {
		err = s.DB.UpgradeUser(user.Id)
		if err != nil {
			log.Printf("Error upgrading user: %s", err)
			handlers.RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	PORT := "8080"
	if os.Getenv("PORT") != "" {
		PORT = os.Getenv("PORT")
	}

	router := chi.NewRouter()
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *dbg {
		db.DeleteDB("database.json")
	}

	db, err := db.NewDB("database.json")
	state := &State{DB: db, JWTSecret: jwtSecret, RevokedTokens: make(map[string]time.Time)}
	if err != nil {
		log.Fatal(err)
		return
	}

	fsHandler := state.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir("."))))
	router.Handle("/app", fsHandler)
	router.Handle("/app/*", fsHandler)
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.WriteHeader(200)
		const page = `<html>
	<head></head>
	<body>
		<p>Hi Docker, I pushed a new version!</p>
	</body>
	</html>
	`
		w.Write([]byte(page))
	})

	apiRouter := chi.NewRouter()
	apiRouter.Get("/healthz", healthzHandler)
	apiRouter.Get("/chirps", state.getChirpsHandler)
	apiRouter.Get("/chirps/{chirpId}", state.getChirpHandler)
	apiRouter.Delete("/chirps/{chirpID}", state.deleteChirpHandler)
	apiRouter.Post("/chirps", state.createChirpHandler)
	apiRouter.Post("/users", state.createUserHandler)
	apiRouter.Put("/users", state.updateUserHandler)
	apiRouter.Post("/login", state.loginHandler)
	apiRouter.Post("/refresh", state.refreshHandler)
	apiRouter.Post("/revoke", state.revokeHandler)
	apiRouter.Post("/polka/webhooks", state.polkaWebhookHandler)
	router.Mount("/api", apiRouter)

	adminRouter := chi.NewRouter()
	adminRouter.Get("/metrics", state.metricsHandler)
	router.Mount("/admin", adminRouter)

	corsMux := middlewareCors(router)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", PORT),
		Handler: corsMux,
	}

	log.Fatal(server.ListenAndServe())
}
