"""Differential conformance harness: mockdr against the real products.

Sends one request description to both a mocked and a real vendor endpoint,
normalises away the differences that are meaningless, and reports the rest.
"""
