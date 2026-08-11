import os

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    required = {
        "POSTGRES_USER": os.getenv("POSTGRES_USER"),
        "POSTGRES_PASSWORD": os.getenv("POSTGRES_PASSWORD"),
        "POSTGRES_DB": os.getenv("POSTGRES_DB"),
        "DATABASE_HOST": os.getenv("DATABASE_HOST"),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError(
            "Faltan variables de base de datos: " + ", ".join(sorted(missing))
        )
    DATABASE_URL = URL.create(
        drivername="postgresql+psycopg2",
        username=required["POSTGRES_USER"],
        password=required["POSTGRES_PASSWORD"],
        host=required["DATABASE_HOST"],
        port=int(os.getenv("DATABASE_PORT", "5432")),
        database=required["POSTGRES_DB"],
    )

engine_options = {"pool_pre_ping": True}
if not str(DATABASE_URL).startswith("sqlite"):
    engine_options.update(
        pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
        pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
        pool_recycle=1800,
    )

engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

