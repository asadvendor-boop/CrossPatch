import os
import sys
from pathlib import Path

import pytest

VICTIM_SRC = Path(__file__).parents[1] / "src"
if str(VICTIM_SRC) not in sys.path:
    sys.path.insert(0, str(VICTIM_SRC))


@pytest.fixture
def database_url():
    value = os.environ.get("CROSSPATCH_TEST_DATABASE_URL")
    if value is None:
        pytest.skip("CROSSPATCH_TEST_DATABASE_URL is required for the real PostgreSQL contract")
    return value


@pytest.fixture
def database(database_url):
    from victim.db import Database

    instance = Database(database_url)
    instance.initialize()
    instance.reset()
    yield instance
    instance.reset()
