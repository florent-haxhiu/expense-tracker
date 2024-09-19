"""
Expense Tracker API

Author: Florent Haxhiu
Documetation: https://www.github.com/florent-haxhiu/expense-tracker

"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from models.users import User, UserInDB

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehasheds",
        "disabled": False,
        "expenses": None,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
        "expenses": None,
    },
}


def fake_hash_password(password: str) -> str:
    return "fakehashed" + password


def get_user(db, username: str) -> UserInDB | None:
    """If username is in db then return user object in UserInDB"""
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token) -> UserInDB | None:
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """Decodes token and returns user is not None"""
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User | HTTPException:
    """Checks if the user is active """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """Allows a User to connect to the API

    Read from a fake db and validate that it exists
    Pass down all the data to the UserInDB model
    Get the unhashed password and compare to the one in the form_data
    Return the access token and token type if they match

    Throw HTTPExceptions if the user_dict doesn't exist or if the passwords don't match

    .. note:
        Unsecure version

    """
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user
