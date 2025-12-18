import pytest
import os
import json

@pytest.fixture
def single_cve_data():
    """
    Provides single CVE data for testing purposes.
    """
    with open(os.path.join(os.path.dirname(__file__), "test_data/single-cve.json"), "r") as f:
        return json.load(f)

@pytest.fixture
def no_cve_data():
    """
    Provides empty response signalling no matching CVEs.
    """
    with open(os.path.join(os.path.dirname(__file__), "test_data/no-cve.json"), "r") as f:
        return json.load(f)
    
@pytest.fixture
def multi_cve_data():
    """
    Provides data for multiple CVEs.
    """
    with open(os.path.join(os.path.dirname(__file__), "test_data/multi-cve.json"), "r") as f:
        return json.load(f)