"""FastAPI dependency injection providers for Database, Storage, and Celery."""

from __future__ import annotations

import io
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from pecff.config import settings

# Async Engine and SessionMaker
_engine = None
_async_session_factory = None


def get_engine() -> Any:
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _async_session_factory
    if _async_session_factory is None:
        engine = get_engine()
        _async_session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _async_session_factory


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide an asynchronous SQLAlchemy session with automatic commit/rollback."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


class StorageService:
    """MinIO / Object Storage client with streaming and local fallback support."""

    def __init__(self, local_fallback_dir: Path | str = "data/storage") -> None:
        self.local_dir = Path(local_fallback_dir)
        self.local_dir.mkdir(parents=True, exist_ok=True)
        self._minio_client: Any = None

    def _get_minio(self) -> Any:
        if self._minio_client is None:
            try:
                from minio import Minio

                self._minio_client = Minio(
                    settings.minio_endpoint,
                    access_key=settings.minio_access_key,
                    secret_key=settings.minio_secret_key,
                    secure=settings.minio_secure,
                )
            except Exception:
                self._minio_client = None
        return self._minio_client

    def put_stream(
        self, bucket: str, object_name: str, stream: io.BytesIO | Any, length: int
    ) -> str:
        """Stream upload an object to MinIO or local fallback storage."""
        minio = self._get_minio()
        if minio:
            try:
                if not minio.bucket_exists(bucket):
                    minio.make_bucket(bucket)
                minio.put_object(
                    bucket_name=bucket,
                    object_name=object_name,
                    data=stream,
                    length=length,
                )
                return f"minio://{bucket}/{object_name}"
            except Exception:
                pass

        # Local storage fallback
        dest_path = self.local_dir / bucket / object_name
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(stream, "seek"):
            stream.seek(0)
        with open(dest_path, "wb") as f:
            if hasattr(stream, "read"):
                chunk = stream.read(65536)
                while chunk:
                    f.write(chunk)
                    chunk = stream.read(65536)
            elif isinstance(stream, bytes):
                f.write(stream)
            elif isinstance(stream, str):
                f.write(stream.encode("utf-8"))
        return str(dest_path)

    def get_presigned_put_url(self, bucket: str, object_name: str, expires_sec: int = 3600) -> str:
        """Generate a presigned PUT URL for direct client upload."""
        minio = self._get_minio()
        if minio:
            try:
                from datetime import timedelta

                return str(
                    minio.get_presigned_url(
                        method="PUT",
                        bucket_name=bucket,
                        object_name=object_name,
                        expires=timedelta(seconds=expires_sec),
                    )
                )
            except Exception:
                pass
        return f"http://{settings.api_host}:{settings.api_port}/api/v1/pcaps/direct_upload/{bucket}/{object_name}"


_storage_instance = StorageService()


def get_storage_service() -> StorageService:
    """Dependency provider for storage service."""
    return _storage_instance
