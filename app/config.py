# app/config.py
import os
from pydantic import BaseSettings


class Settings(BaseSettings):
    # ===== Cloud SQL 相关配置 =====
    DB_USER: str = os.getenv("DB_USER", "a123")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "123@Abcd")
    DB_NAME: str = os.getenv("DB_NAME", "ms1_users_db")

    INSTANCE_CONNECTION_NAME: str = os.getenv(
        "INSTANCE_CONNECTION_NAME",
        "coms4153-cloud-surfers:us-central1:a123",
    )


    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change-me-secret")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60")
    )

    APP_HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))


settings = Settings()
