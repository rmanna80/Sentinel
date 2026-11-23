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


def test_database_created_before_tables_were_added_to_0001_is_repaired(tmp_path):
    """A database stamped 0001 before advisories, field data and behaviour tables were added to that revision."""
    from sqlalchemy import text

    late = ["field_observations", "field_captures", "advisories", "behavior_detections", "audit_signatures"]
    url = f"sqlite:///{(tmp_path / 'old.db').as_posix()}"
    upgrade_to_head(url)
    engine = create_engine(url)
    with engine.begin() as conn:  # put it back in the state such a database is really in
        for table in late:
            conn.execute(text(f"DROP TABLE {table}"))
        conn.execute(text("UPDATE alembic_version SET version_num = '0001'"))
        conn.execute(text("INSERT INTO users (username, password_hash, is_active, failed_logins, created_at) "
                          "VALUES ('ryan', 'x', 1, 0, '2026-10-26 00:00:00')"))
    assert not set(late) & set(inspect(engine).get_table_names())
    engine.dispose()

    upgrade_to_head(url)

    engine = create_engine(url)
    assert set(inspect(engine).get_table_names()) - {"alembic_version"} == set(Base.metadata.tables)
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []  # tables, columns and indexes
        assert conn.execute(text("SELECT username FROM users")).scalar_one() == "ryan"  # existing data untouched
        assert conn.execute(text("SELECT count(*) FROM advisories")).scalar_one() == 0
    upgrade_to_head(url)  # and running it again changes nothing
