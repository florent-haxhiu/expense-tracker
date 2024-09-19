"""
Expense Tracker API

Author: Florent Haxhiu
Documetation: https://www.github.com/florent-haxhiu/expense-tracker

"""

import fastapi
import pydantic

app = fastapi.FastAPI()


class Something(pydantic.BaseModel):
    message: str


@app.get("/")
async def root() -> Something:
    return Something(message="Hello World")

