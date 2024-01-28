module github.com/jerrydevs/go_server_test

go 1.21.5

replace chirps/handlers v1.0.0 => ./handlers

replace chirps/db v1.0.0 => ./db

require (
	chirps/db v1.0.0
	chirps/handlers v1.0.0
	github.com/go-chi/chi/v5 v5.0.11
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	golang.org/x/crypto v0.17.0 // indirect
)
