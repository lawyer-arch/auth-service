from datetime import datetime
from uuid import uuid4
from sqlalchemy import String, Boolean, DateTime, Integer, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base



""" класс "пользовтель - User" должен содержать поля:
 3.1. Схема базы данных (PostgreSQL)
-- Пользователи
user (
    id UUID PRIMARY KEY DEFAULT uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),  -- NULL для OAuth пользователей
    username VARCHAR(255) NULL
    first_name VARCHAR(255) NULL
    last_name VARCHAR(255) NULL
    full_name VARCHAR(255), NULL
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE
);
"""
class User(Base):
    
    __tablename__ = "users"
    
    id: Mapped[UUID] =  mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )
    email: Mapped[str] = mapped_column(
        String,
        unique=True,
        nullable=False
    )
    password_hash: Mapped[str] = mapped_column(
        String,
        nullable=True
    )
    username: Mapped[str] = mapped_column(
        String(255),
        nullable=True
    )
    first_name: Mapped[str] = mapped_column(
        String(255),
        nullable=True
    )
    last_name: Mapped[str] = mapped_column(
        String(255),
        nullable=True
    )
    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=True
    ) 
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )
    last_login_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0
    )
    locked_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
