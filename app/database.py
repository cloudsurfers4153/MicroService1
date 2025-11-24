import logging
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sqlalchemy.pool import NullPool
from google.cloud.sql.connector import Connector, IPTypes


from app.config import settings

logger = logging.getLogger(__name__)

# 全局对象，整个应用只初始化一次
engine = None
SessionLocal = None
connector: Connector | None = None

# 恢复 Base，确保其他模块可以 `from app.database import Base` 正常工作
Base = declarative_base()


def get_connection():
    """
    使用 Cloud SQL Python Connector 创建到 Cloud SQL 的连接。
    这个函数会被 SQLAlchemy 的 engine 通过 creator 回调使用。
    """
    global connector

    # 只初始化一次 Connector
    if connector is None:
        # 使用 PUBLIC IP 连接实例（实例本身有公网 IP）
        connector = Connector(ip_type=IPTypes.PUBLIC)

    conn = connector.connect(
        settings.INSTANCE_CONNECTION_NAME,
        "pymysql",
        user=settings.DB_USER,
        password=settings.DB_PASSWORD,
        db=settings.DB_NAME,
    )
    return conn


def init_database():

    global engine, SessionLocal

    if engine is not None:

        return

    logger.info(f"Connecting to Cloud SQL: {settings.INSTANCE_CONNECTION_NAME}")

    # 使用 Cloud SQL Connector 提供的 connection，而不是自己写 URL
    engine = create_engine(
        "mysql+pymysql://",
        creator=get_connection,
        poolclass=NullPool,
    )

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("Database engine and session factory initialized")


def init_db():

    if engine is None:
        init_database()

    logger.info("Creating database tables if they don't exist...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


def get_db() -> Generator[Session, None, None]:

    if SessionLocal is None:
        init_database()

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def close_database():
    """
    关闭 Cloud SQL Connector 和 SQLAlchemy Engine。
    一般在应用关闭时调用。
    """
    global connector, engine, SessionLocal

    if connector is not None:
        connector.close()
        connector = None
        logger.info("Cloud SQL connector closed")

    if engine is not None:
        engine.dispose()
        engine = None
        logger.info("Database engine disposed")

    SessionLocal = None
