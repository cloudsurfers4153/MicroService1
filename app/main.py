from fastapi import FastAPI, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from app import crud, models, schemas
from app.database import engine, Base
from app.deps import get_db, get_current_user
from app.auth import create_access_token
from datetime import timedelta
from app.config import settings

# create tables if not using alembic (for dev only)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="MS1 - Users Service")

@app.post("/users", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register_user(user_in: schemas.UserCreate, response: Response, db: Session = Depends(get_db)):
    # uniqueness checks
    if crud.get_user_by_email(db, user_in.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if crud.get_user_by_username(db, user_in.username):
        raise HTTPException(status_code=400, detail="Username already taken")
    user = crud.create_user(db, user_in)
    response.headers["Location"] = f"/users/{user.id}"
    return user

@app.post("/sessions", response_model=schemas.Token)
def login_for_access_token(form_data: dict, db: Session = Depends(get_db)):
    """
    Expects JSON body: { "email": "xxx", "password": "yyy" }
    """
    email = form_data.get("email")
    password = form_data.get("password")
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    user = crud.authenticate_user(db, email, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(user.id, expires_delta=access_token_expires)
    return {"access_token": token, "to1ken_type": "bearer"}

@app.get("/users/{user_id}", response_model=schemas.UserOut)
def read_user_profile(user_id: str, db: Session = Depends(get_db), current=Depends(get_current_user)):
    user = crud.get_user(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.patch("/users/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: str, payload: dict, db: Session = Depends(get_db), current=Depends(get_current_user)):
    # allow a user to edit their own profile only
    if current.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this user")
    username = payload.get("username")
    full_name = payload.get("full_name")
    if username and username != current.username and crud.get_user_by_username(db, username):
        raise HTTPException(status_code=400, detail="Username already taken")
    user = crud.update_user_profile(db, current, full_name=full_name, username=username)
    return user

@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: str, db: Session = Depends(get_db), current=Depends(get_current_user)):
    if current.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this user")
    crud.deactivate_user(db, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
