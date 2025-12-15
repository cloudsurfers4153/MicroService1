from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app import crud, models, schemas
from app.deps import get_db, get_current_user
from app.auth import create_access_token
from datetime import timedelta
from app.config import settings

import os
import logging
import requests

from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport.requests import Request as GoogleRequest

logger = logging.getLogger(__name__)

from app.database import init_db, close_database

app = FastAPI(title="MS1 - Users Service")

# Run database initialization during application startup (create tables if needed)
@app.on_event("startup")
def on_startup():
    init_db()


# Clean up database connector / engine on shutdown
@app.on_event("shutdown")
def on_shutdown():
    close_database()


# ---------------- Replace reading JSON file: embed client secrets dict here ----------------
# JSON content provided by the user has been pasted below as a Python dict.
# If you want to override values via environment variables, you can still do so (example shown for redirect URI).
CLIENT_SECRETS = {
    "web": {
        "client_id": "608197196549-a51rsrgcgujvp8b765hj2pm1l40td4t1.apps.googleusercontent.com",
        "project_id": "coms4153-cloud-surfers",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": "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",
        "redirect_uris": [
            "http://localhost:8000/auth/google/callback",
            "https://microservice1-608197196549.us-central1.run.app/auth/google/callback",
            "https://compositemicroservice-608197196549.us-central1.run.app/composite/auth/google/callback",
            "https://storage.googleapis.com/movie-platform-frontend/index.html",
            "https://compositemicroservice-608197196549.us-central1.run.app/auth/google/callback"
        ]
    }
}

# Google OAuth configuration (we no longer load from file)
# You can still override the redirect URI through environment variable if needed.
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI",
    "https://microservice1-608197196549.us-central1.run.app/auth/google/callback",
)
GOOGLE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

# In-memory state store for demonstration/testing only.
# In production, use a persistent store (Redis/DB) or signed state cookies.
_state_store = {}


def _get_client_id_from_config(client_config: dict):
    """
    Extract client_id from the embedded client config dict.
    Return None on failure.
    """
    try:
        client_id = client_config.get("web", {}).get("client_id") or client_config.get("installed", {}).get("client_id")
        return client_id
    except Exception as e:
        logger.warning("Failed to read client id from embedded config: %s", e)
        return None


# ---------------- Standard user endpoints ----------------

@app.post("/users", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register_user(user_in: schemas.UserCreate, response: Response, db: Session = Depends(get_db)):
    """
    Register a new user using email/username/password.
    """
    if crud.get_user_by_email(db, user_in.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if crud.get_user_by_username(db, user_in.username):
        raise HTTPException(status_code=400, detail="Username already taken")
    user = crud.create_user(db, user_in)
    response.headers["Location"] = f"/users/{user.id}"
    return user


@app.post("/sessions", response_model=schemas.Token)
def login_for_access_token(form_data: schemas.UserLogin, db: Session = Depends(get_db)):
    """
    Login with email/password. Expects JSON body matching schemas.UserLogin.
    Returns a JWT access token.
    """
    email = form_data.email
    password = form_data.password
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    user = crud.authenticate_user(db, email, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(user.id, expires_delta=access_token_expires)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/users/{user_id}", response_model=schemas.UserOut)
def read_user_profile(user_id: str, db: Session = Depends(get_db), current: models.User = Depends(get_current_user)):
    """
    Read a user's profile. Requires authentication.
    """
    user = crud.get_user(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.patch("/users/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: str, payload: schemas.UserUpdate, db: Session = Depends(get_db), current: models.User = Depends(get_current_user)):
    """
    Update user's profile (username or full_name). Only the owner may update.
    """
    if current.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this user")
    username = payload.username
    full_name = payload.full_name
    if username and username != current.username and crud.get_user_by_username(db, username):
        raise HTTPException(status_code=400, detail="Username already taken")
    user = crud.update_user_profile(db, current, full_name=full_name, username=username)
    return user


@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: str, db: Session = Depends(get_db), current: models.User = Depends(get_current_user)):
    """
    Deactivate a user account. Only the owner may delete.
    """
    if current.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this user")
    crud.deactivate_user(db, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------- Google OAuth endpoints ----------------
@app.get("/auth/google/url")
def google_auth_url():
    """
    Create a Google OAuth Flow and return the authorization URL and state.
    Frontend should redirect the user to the returned auth_url.
    Response: { "auth_url": "...", "state": "..." }
    """
    try:
        # Use from_client_config to avoid loading from a file
        flow = Flow.from_client_config(
            CLIENT_SECRETS,
            scopes=GOOGLE_SCOPES,
            redirect_uri=GOOGLE_REDIRECT_URI,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create OAuth flow: {e}")

    auth_url, state = flow.authorization_url(access_type="offline", prompt="consent")
    _state_store[state] = True
    return {"auth_url": auth_url, "state": state}


@app.get("/auth/google/callback")
def google_callback(request: Request, db: Session = Depends(get_db)):
    """
    Google OAuth callback endpoint.

    Steps:
      - Validate the state that was stored earlier
      - Exchange the authorization code for tokens via flow.fetch_token()
      - Verify the ID token and extract user info
      - Ensure the user exists in the DB; create if missing
      - Issue an application JWT and return it together with Google tokens and id_info

    Returned JSON:
      {
        "user": { id, email, username, full_name, is_new },
        "google_tokens": { access_token, refresh_token, id_token, expiry },
        "id_info": { ... },
        "access_token": "<app_jwt>",
        "token_type": "bearer"
      }
    """
    url = str(request.url)
    state = request.query_params.get("state")
    if not state or not _state_store.pop(state, None):
        # Fix for Cloud Run: internal requests use HTTP but external is HTTPS
        # Check X-Forwarded-Proto header set by the load balancer
        if request.headers.get("x-forwarded-proto") == "https" and url.startswith("http://"):
            url = url.replace("http://", "https://", 1)
        raise HTTPException(status_code=400, detail="Invalid or missing OAuth state.")
    try:
        flow = Flow.from_client_config(
            CLIENT_SECRETS,
            scopes=GOOGLE_SCOPES,
            state=state,
            redirect_uri=GOOGLE_REDIRECT_URI,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create OAuth flow: {e}")

    try:
        flow.fetch_token(authorization_response=url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch token: {e}")

    credentials = flow.credentials

    client_id = _get_client_id_from_config(CLIENT_SECRETS)
    try:
        id_info = id_token.verify_oauth2_token(credentials.id_token, GoogleRequest(), client_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"ID token verification failed: {e}")

    email = id_info.get("email")
    name = id_info.get("name")

    if not email:
        raise HTTPException(status_code=400, detail="Google account has no email.")

    # Check the DB for an existing user; create a new one if missing
    user = crud.get_user_by_email(db, email)
    created = False
    if not user:
        user = crud.create_user_oauth(db, email=email, full_name=name)
        created = True

    # Issue application JWT
    access_token_expires = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    app_token = create_access_token(user.id, expires_delta=access_token_expires)

    response = {
        "user": {
            "id": user.id,
            "email": user.email,
            "username": getattr(user, "username", None),
            "full_name": getattr(user, "full_name", None),
            "is_new": created,
        },
        "google_tokens": {
            "access_token": getattr(credentials, "token", None),
            "refresh_token": getattr(credentials, "refresh_token", None),
            "id_token": getattr(credentials, "id_token", None),
            "expiry": credentials.expiry.isoformat() if credentials.expiry else None,
        },
        "id_info": id_info,
        "access_token": app_token,
        "token_type": "bearer",
    }
    return JSONResponse(response)


@app.post("/auth/google/logout")
def google_logout(payload: dict = None, db: Session = Depends(get_db), current: models.User = Depends(get_current_user)):
    """
    Optional Google token revocation endpoint.

    - Requires application authorization (Bearer app JWT).
    - If request body contains {"google_token": "<token>"}, attempt to revoke it via Google's revoke endpoint.
    Returns: { "msg": "ok", "user_id": "<id>", "google_revoked": true/false/null }
    """
    google_token = None
    if payload:
        google_token = payload.get("google_token")

    revoked = None
    if google_token:
        try:
            r = requests.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": google_token},
                headers={"content-type": "application/x-www-form-urlencoded"},
                timeout=5,
            )
            revoked = (r.status_code == 200)
        except Exception:
            revoked = False

    # The application is stateless regarding JWTs; the client should delete its copy of the app token.
    return {"msg": "ok", "user_id": current.id, "google_revoked": revoked}


# #-------- test --------
# from fastapi.staticfiles import StaticFiles
# from fastapi.middleware.cors import CORSMiddleware
#
# #Allow http local testing of OAuth (do not enable in production)
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
#
# #Allow CORS for development (adjust origins in production)
# app.add_middleware(
#    CORSMiddleware,
#    allow_origins=["*"],  # for development only; use specific origins in production
#    allow_credentials=True,
#    allow_methods=["*"],
#    allow_headers=["*"],
# )
#
#
# app.mount("/static", StaticFiles(directory="static"), name="static")
