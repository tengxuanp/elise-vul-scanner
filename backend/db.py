# backend/db.py
import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

# --- SA 2.x / 1.4 compatible Base ---
try:
    from sqlalchemy.orm import DeclarativeBase
    class Base(DeclarativeBase): ...
except ImportError:
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()

# Resolve repo root -> data/evidence.db (independent of CWD)
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_URL = os.getenv("DB_URL", f"sqlite:///{(DATA_DIR / 'evidence.db').as_posix()}")

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
    future=True,
)

# SQLite PRAGMAs
if DB_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
