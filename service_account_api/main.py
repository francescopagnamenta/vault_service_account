from fastapi import FastAPI, HTTPException, Depends
import hvac
import os
from typing import Dict
from pydantic import BaseModel

app = FastAPI()

# Vault configuration
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "myroot")
VAULT_PATH = "secret/service_accounts"

client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

class ServiceAccount(BaseModel):
    name: str
    role: str
    secret: str

class ServiceAccountValidation(BaseModel):
    name: str
    secret: str

def check_vault_connection():
    if not client.is_authenticated():
        raise HTTPException(status_code=500, detail="Failed to authenticate with Vault")

@app.post("/service_accounts/")
def create_service_account(account: ServiceAccount):
    check_vault_connection()
    client.secrets.kv.v2.create_or_update_secret(
        path=f"{VAULT_PATH}/{account.name}",
        secret={"role": account.role, "secret": account.secret}
    )
    return {"message": "Service account created", "name": account.name}

@app.get("/service_accounts/{name}")
def get_service_account(name: str):
    check_vault_connection()
    secret_response = client.secrets.kv.v2.read_secret_version(path=f"{VAULT_PATH}/{name}")
    if not secret_response:
        raise HTTPException(status_code=404, detail="Service account not found")
    return secret_response["data"]["data"]

@app.get("/service_accounts/", dependencies=[Depends(check_vault_connection)])
def get_all_service_accounts():
    secrets = client.secrets.kv.v2.list_secrets(path=VAULT_PATH)
    if not secrets or "data" not in secrets:
        return {"service_accounts": []}
    return {"service_accounts": secrets["data"]["keys"]}


@app.post("/service_accounts/validate")
def validate_service_account(account: ServiceAccountValidation):
    check_vault_connection()
    try:
        secret_response = client.secrets.kv.v2.read_secret_version(path=f"{VAULT_PATH}/{account.name}")
        stored_data = secret_response["data"]["data"]
        if stored_data["secret"] == account.secret:
            return {"valid": True, "message": "Service account is valid"}
        else:
            return {"valid": False, "message": "Invalid credentials"}
    except Exception:
        raise HTTPException(status_code=404, detail="Service account not found")