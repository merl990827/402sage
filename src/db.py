# src/db.py
from sqlmodel import SQLModel
from sqlalchemy import create_engine
from src.config import settings

# Use Postgres in prod, SQLite file in dev if DATABASE_URL is missing
DATABASE_URL = settings.DATABASE_URL or "sqlite:///./data.db"

# Extra kwargs: stable connections and sqlite compatibility
engine_kwargs = {"pool_pre_ping": True}
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args, **engine_kwargs)

def init_db() -> None:
    # Import your models so all tables are registered on SQLModel.metadata
    from src import models  # noqa: F401
    SQLModel.metadata.create_all(engine)  # creates tables if they don't exist
