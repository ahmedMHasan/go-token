package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"time"
)

var secretKey = []byte("YourSecretKey")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Create a map to store revoked tokens
var revokedTokens = make(map[string]bool)

// Create a map to store the last valid token for each username
var lastValidTokens = make(map[string]string)

func unixTimestampToTime(expirationTime int64) time.Time {
	return time.Unix(expirationTime, 0)
}

func generateJWT(username string) (string, int64, error) {

	// Set the expiration time for the token
	expirationTime := time.Now().Add(time.Hour * 1).Unix()

	// Create the JWT claims with the username and expiration time
	claims := jwt.MapClaims{
		"username": username,
		"exp":      expirationTime,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expirationTime, nil
}

func verifyToken(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Token")

	// Check if the token is present
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		response := map[string]interface{}{
			"status":  401,
			"message": "Unauthorized",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("Invalid token signing method")
		}
		return secretKey, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		response := map[string]interface{}{
			"status":  401,
			"message": "Unauthorized",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if token.Valid {
		// Check if a valid token exists for this username in the lastValidTokens map
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			username := claims["username"].(string)
			if lastToken, ok := lastValidTokens[username]; ok && lastToken == tokenString {
				// The token matches the last valid token for this username
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				response := map[string]interface{}{
					"status":  200,
					"message": "Logged In",
				}
				json.NewEncoder(w).Encode(response)
				return
			}
		}
	}

	// The token is not valid or doesn't match the last valid token
	w.WriteHeader(http.StatusUnauthorized)
	response := map[string]interface{}{
		"status":  401,
		"message": "Unauthorized",
	}
	json.NewEncoder(w).Encode(response)
}

func generateToken(w http.ResponseWriter, r *http.Request) {
	// Parse the JSON request body into the Credentials struct
	var credentials Credentials
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		response := map[string]interface{}{
			"status":  400,
			"message": "Bad Request",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if a valid token exists for this username in the lastValidTokens map
	if lastToken, ok := lastValidTokens[credentials.Username]; ok {
		// Parse the last valid token to check if it's still valid
		token, err := jwt.Parse(lastToken, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("Invalid token signing method")
			}
			return secretKey, nil
		})

		if err == nil && token.Valid {
			// The last token is still valid, return it along with its expiration time
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				response := map[string]interface{}{
					"status":  500,
					"message": "Error parsing token claims",
				}
				json.NewEncoder(w).Encode(response)
				return
			}

			expiration := int64(claims["exp"].(float64))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := map[string]interface{}{
				"status":     200,
				"token":      lastToken,
				"expiration": unixTimestampToTime(expiration),
				"message":    "Token retrieved successfully",
			}
			json.NewEncoder(w).Encode(response)
			return
		}
	}

	// Generate a new JWT token for the specified username
	token, expirationDate, err := generateJWT(credentials.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		response := map[string]interface{}{
			"status":  500,
			"message": "Error generating JWT",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Store the newly generated token as the last valid token
	lastValidTokens[credentials.Username] = token

	expiration := int64(expirationDate)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]interface{}{
		"status":     200,
		"token":      token,
		"expiration": unixTimestampToTime(expiration),
		"message":    "Token generated successfully",
	}
	json.NewEncoder(w).Encode(response)
}

func destroyToken(w http.ResponseWriter, r *http.Request) {
	// Parse the JSON request body into the Credentials struct
	var credentials Credentials
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		response := map[string]interface{}{
			"status":  400,
			"message": "Bad Request",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if the provided username and password are correct (you should implement this logic)

	// Check if a valid token exists for this username
	if lastToken, ok := lastValidTokens[credentials.Username]; ok {
		// Parse the last valid token to check if it's still valid
		token, err := jwt.Parse(lastToken, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("Invalid token signing method")
			}
			return secretKey, nil
		})

		if err == nil && token.Valid {
			// The last token is still valid, remove it from the lastValidTokens map
			delete(lastValidTokens, credentials.Username)

			// Return a success response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := map[string]interface{}{
				"status":  200,
				"message": "Token destroyed successfully",
			}
			json.NewEncoder(w).Encode(response)
			return
		}
	}

	// If no valid token exists for this username, return an error response
	w.WriteHeader(http.StatusUnauthorized)
	response := map[string]interface{}{
		"status":  401,
		"message": "Unauthorized",
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/generateToken", generateToken)
	http.HandleFunc("/verifyToken", verifyToken)
	http.HandleFunc("/destroyToken", destroyToken)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Error starting the server:", err)
		return
	}
}
