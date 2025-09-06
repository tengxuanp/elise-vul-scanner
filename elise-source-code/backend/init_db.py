# backend/init_db.py
from pathlib import Path
from .db import engine, Base

Path("data").mkdir(exist_ok=True)
Base.metadata.create_all(bind=engine)
print("DB initialized -> data/evidence.db")
