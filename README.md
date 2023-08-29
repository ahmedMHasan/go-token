# Go Token - Golang HTTP Application for JWT Authentication

Go Token is a simple Golang HTTP application that provides endpoints for generating and verifying JSON Web Tokens (JWT) for user authentication.

This Go application provides token management functionalities, including token generation, token verification, and token destruction. It uses JSON Web Tokens (JWTs) to secure your endpoints and manage user sessions.

## Prerequisites

Before running this application, make sure you have the following prerequisites installed on your system:

- Go (Golang): You can download and install Go from [https://golang.org/dl/](https://golang.org/dl/).

## Getting Started

1. Clone the repository:

```bash
   git clone https://github.com/yourusername/go-token.git
   cd go-token
```

2. Install the required packages by running:

```bash
   go get github.com/dgrijalva/jwt-go
```

3. Build and run the project:

```sh
   go run main.go
```

The application will start and listen on port 8080.


## Endpoints

### Generate Token

- **Endpoint:** `/generateToken`
- **Method:** POST
- **Description:** Generates a JWT token for a specified username.
- **Usage:** Send a POST request to this endpoint with a JSON body containing the `username` and `password` for the user you want to authenticate. The endpoint will return a JWT token along with its expiration time.

  **Example using cURL:**
  ```bash
  curl -X POST -d '{"username": "your_username", "password": "your_password"}' http://localhost:8080/generateToken
  ```

### Verify Token

- **Endpoint:** `/verifyToken`
- **Method:** GET
- **Description:** Verifies the JWT token provided in the request header.
- **Usage:** Access this endpoint with a valid JWT token in the "Token" header to check if the token is valid. It will return "Logged In" if the token is valid; otherwise, it will return "Unauthorized."

  **Example using cURL:**
  ```bash
  curl -H "Token: your_jwt_token" http://localhost:8080/verifyToken
  ```

### Destroy Token

- **Endpoint:** `/destroyToken`
- **Method:** POST
- **Description:** Terminates the session (token) based on the username and password.
- **Usage:** Send a POST request to this endpoint with a JSON body containing the `username` and `password` of the user for whom you want to destroy the token. If the provided credentials are correct, and a valid token exists for the user, the token will be destroyed, and subsequent requests with that token will be unauthorized.

  **Example using cURL:**
  ```bash
  curl -X POST -d '{"username": "your_username", "password": "your_password"}' http://localhost:8080/destroyToken
  ```

## Token Management

- Tokens are generated with an expiration time of **1 Hour** for demonstration purposes. You can modify the `generateJWT` function to set a different expiration time as needed.

- The application keeps track of the last valid token for each username. If a user generates a new token while a valid token exists, the application will return the last valid token along with its expiration time.

- To destroy a token, send a request to the `/destroyToken` endpoint with valid credentials. If the token is valid and matches the last valid token for the user, it will be destroyed.

## Usage with Postman

1. Open Postman or any API testing tool.

2. Create a new request for each of the following endpoints:

   - **Generate Token:** Set the request URL to `http://localhost:8080/generateToken`, and send the request with a JSON body containing `username` and `password`. You will receive a JWT token in the response.

   - **Verify Token:** Set the request URL to `http://localhost:8080/verifyToken`. Add a header with the key "Token" and the value being the JWT token obtained from the "Generate Token" request. Send the request to verify the token.

   - **Destroy Token:** Set the request URL to `http://localhost:8080/destroyToken`. Send a POST request with a JSON body containing `username` and `password` to destroy the token for the specified user.

## Project Structure

- `main.go`: The main Go source code file.
- `README.md`: This README file.
- `.gitignore`: Git ignore file.
- `LICENSE`: License information.

## Contributing

Contributions are welcome! If you have any suggestions or find any issues, please open an issue or create a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the authors of the `github.com/dgrijalva/jwt-go` library for their work on JWT token handling in Go.

```css
Feel free to customize this template to fit your specific project details and requirements.
```