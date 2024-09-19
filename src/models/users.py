import pydantic


class Expense(pydantic.BaseModel):
    id: int
    name: str
    cost: float


class User(pydantic.BaseModel):
    username: str
    email: pydantic.EmailStr | None
    full_name: str | None
    expenses: list[Expense] | None
    disabled: bool | None


class UserInDB(User):
    hashed_password: str
