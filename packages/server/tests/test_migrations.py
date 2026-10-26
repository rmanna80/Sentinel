"""The Alembic migrations must build exactly the schema the models describe."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sentinel_server import models  # noqa: F401 - registers every table
from sentinel_server.db import Base
from sentinel_server.migrate import upgrade_to_head
from sqlalchemy import create_engine, inspect


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    upgrade_to_head(url)
    engine = create_engine(url)
    tables = set(inspect(engine).get_table_names()) - {"alembic_version"}
    assert tables == set(Base.metadata.tables)
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []


def test_upgrade_is_idempotent(tmp_path):
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    upgrade_to_head(url)
    upgrade_to_head(url)
