import pytest
import os
import hashlib
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_start_discovery():
    pass
