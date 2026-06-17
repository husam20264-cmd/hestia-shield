"""
Pytest configuration for Hestia Shield v1.1.0 tests
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from fastapi.testclient import TestClient


@pytest.fixture(scope="function")
def test_storage():
    temp_dir = tempfile.mkdtemp()
    data_dir = Path(temp_dir)

    from hestia.storage import Storage
    storage = Storage(data_dir=data_dir, store_raw_inputs=False)

    import asyncio
    asyncio.run(storage.initialize())

    yield storage

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def test_client(test_storage):
    """Uses test_storage so API keys created in test_storage work with the client."""
    from hestia import api as hestia_api
    from hestia.auth import AuthManager
    from hestia.decision_engine import DecisionEngine
    from hestia.rules_engine import RulesEngine
    from hestia.classifier import TextClassifier
    from hestia.attack_memory import AttackMemory

    hestia_api.storage = test_storage
    hestia_api.auth_manager = AuthManager(test_storage)
    hestia_api.tenants.clear()

    from hestia.queue import configure_queue
    configure_queue(test_storage)

    def mock_get_tenant(tenant_id: str):
        if tenant_id not in hestia_api.tenants:
            hestia_api.tenants[tenant_id] = DecisionEngine(
                rules_engine=RulesEngine(),
                classifier=TextClassifier(),
                attack_memory=AttackMemory()
            )
        return hestia_api.tenants[tenant_id]

    hestia_api.get_tenant = mock_get_tenant

    client = TestClient(hestia_api.app)

    yield client

    hestia_api.tenants.clear()


@pytest.fixture(scope="function")
def test_token(test_storage, test_client):
    import asyncio
    key_data = asyncio.run(test_storage.create_api_key("ten_test", "admin"))
    response = test_client.post(
        "/v1/token",
        json={"api_key": key_data["key"]}
    )
    assert response.status_code == 200, f"Token creation failed: {response.text}"
    return response.json()["token"]


@pytest.fixture(scope="function")
def test_admin_token(test_storage, test_client):
    import asyncio
    key_data = asyncio.run(test_storage.create_api_key("ten_test", "admin"))
    response = test_client.post(
        "/v1/token",
        json={"api_key": key_data["key"]}
    )
    assert response.status_code == 200
    return response.json()["token"]


@pytest.fixture(scope="function")
def test_viewer_token(test_storage, test_client):
    import asyncio
    key_data = asyncio.run(test_storage.create_api_key("ten_demo", "viewer"))
    response = test_client.post(
        "/v1/token",
        json={"api_key": key_data["key"]}
    )
    assert response.status_code == 200
    return response.json()["token"]