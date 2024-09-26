from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from models import Token, User
from auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    get_password_hash,
)
from config import ACCESS_TOKEN_EXPIRE_MINUTES
from database import fake_users_db
from datetime import timedelta

from models.expense import ExpenseCreate
from models.users import UserCreate

router = APIRouter()

@router.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@router.post("/signup")
async def signup(user: UserCreate):
    """Allows a User to signup for an account"""

    user_dict = user.model_dump()
    user_dict["hashed_password"] = get_password_hash(user_dict["password"])
    if user_dict["username"] in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )
    fake_users_db[user_dict["username"]] = user_dict

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@router.get("/users/me")
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


@router.post("/expenses")
async def create_expense(expense: ExpenseCreate, current_user: Annotated[User, Depends(get_current_user)]):
    """Allows a User to create an expense"""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create a new expense for the user
    new_expense = expense.model_dump()
    new_expense["user_id"] = current_user.username
    
    # In a real database, you would insert the expense here
    # For now, we'll just add it to the user's expenses in the fake database
    if fake_users_db[current_user.username].get("expenses") is None:
        fake_users_db[current_user.username]["expenses"] = []
    fake_users_db[current_user.username]["expenses"].append(new_expense)
    
    return {"message": "Expense created successfully", "expense": new_expense}
