
# Service Account with FastAPI and Vault

This is a simple backend service built using **FastAPI** that interacts with **HashiCorp Vault** for managing service accounts. It allows creating, retrieving, and validating service accounts stored in Vault. The backend is containerized using **Docker** and can be easily run using **Docker Compose**.

## Features
- **Create Service Account**: Endpoint to create new service accounts with a name, role, and secret.
- **Retrieve Service Account**: Fetch a specific service account by its name.
- **List Service Accounts**: An admin-only endpoint to retrieve all created service accounts.
- **Validate Service Account**: An endpoint to validate if the provided service account name and secret are correct.

## Prerequisites
- Docker and Docker Compose must be installed on your machine.
- HashiCorp Vault will be used in development mode.

## Getting Started

### 1. Clone the Repository
Start by cloning the repository to your local machine:
```bash
git clone git@github.com:francescopagnamenta/vault_service_account.git
cd vault_service_accounts
```

### Set Up Docker and Vault

To set up Vault in development mode and the FastAPI application, use Docker Compose. This will create a container for Vault and the FastAPI service.

Build and Run with Docker Compose
Run the following command to build and start both Vault and FastAPI:

```bash
docker-compose up --build
```

### Interacting with the API

Once the services are running, you can interact with the FastAPI service via the following endpoints.

Create a Service Account
To create a service account, use the following curl command:

```bash
curl -X POST "http://localhost:8000/service_accounts/" \
     -H "Content-Type: application/json" \
     -d '{
           "name": "example-service",
           "role": "read-only",
           "secret": "supersecurepassword"
         }'
```


### Get a Service Account

To retrieve a service account by its name, use this command:

```bash
curl -X GET "http://localhost:8000/service_accounts/example-service"
```

## Create a service account

```
curl -X POST "http://localhost:8000/service_accounts/" \
     -H "Content-Type: application/json" \
     -d '{
           "name": "example-service",
           "role": "read-only",
           "secret": "supersecurepassword"
         }'

```

### Get All Service Accounts

This endpoint allows the admin to get a list of all created service accounts:

```bash
curl -X GET "http://localhost:8000/service_accounts/"
```

### Validate a Service Account

To validate whether the name and secret of a service account are correct, use the following command:


```bash
curl -X POST "http://localhost:8000/service_accounts/validate" \
     -H "Content-Type: application/json" \
     -d '{
           "name": "example-service",
           "secret": "supersecurepassword"
         }'

```

###  Stop the Services

```bash
docker-compose down
```

### Disclaimer

This software was developed with the assistance of ChatGPT by OpenAI. It is intended for educational and experimental use. Please review and adapt it as needed for production environments.