# Auth Service

This service is part of the Customer Management Microservices project. It handles user authentication and authorization using OAuth2.

## Features

- User registration
- Token issuance using OAuth2
- Running on port 8081

## Endpoints

- `GET /account`: Service health check
- `POST /account/register`: Register a new user
- `POST /oauth/token`: Get an access token

## Usage

1. Register a user using the `/account/register` endpoint
2. Obtain an access token using the `/oauth/token` endpoint
3. Use the access token to make authenticated requests to the Data Service