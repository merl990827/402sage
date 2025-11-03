"""Pytest configuration for unit tests."""

import os

# Set DEBUG_MOCK=true before any imports to avoid requiring API keys in unit tests
os.environ.setdefault("DEBUG_MOCK", "true")
