from pydantic import BaseModel
from datetime import datetime

class Expense(BaseModel):
    id: int
    title: str
    description: str
    amount: float
    date: datetime
    user_id: int

class ExpenseCreate(BaseModel):
    title: str
    description: str | None = None
    amount: float
    date: datetime = datetime.now()
    user_id: int = None

