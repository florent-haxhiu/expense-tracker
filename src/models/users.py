import pydantic


class Expense(pydantic.BaseModel):
    id: int
    name: str
    cost: float


class User(pydantic.BaseModel):
    username: str
    email: pydantic.EmailStr | None = None
    full_name: str | None = None
    expenses: list[Expense] | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str
