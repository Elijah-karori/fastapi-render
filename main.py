from typing import Optional
from routers import users
from routers import items
from fastapi import FastAPI

app = FastAPI()
app.include_router(users.router)
app.include_router(items.router)

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/items/{item_id}")
def read_item(item_id: int, q: Optional[str] = None):
    return {"item_id": item_id, "q": q}
