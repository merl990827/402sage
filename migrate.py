# migrate.py
from src.models import *
from src.config import settings
from sqlalchemy import create_engine

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)

print("Creating tables…")
SQLModel.metadata.create_all(engine)
print("✅ Done.")
