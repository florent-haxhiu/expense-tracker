"""
Expense Tracker API

Author: Florent Haxhiu
Documetation: https://www.github.com/florent-haxhiu/expense-tracker

"""

from fastapi import FastAPI
from routes import router

app = FastAPI()

app.include_router(router)
