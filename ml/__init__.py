"""Offline URL feature extraction and ML training utilities.

This package is separate from the Flask rule-based detector in ``app.py``.
It never visits URLs or makes network requests.
"""

from ml.features import FEATURE_NAMES, extract_url_features, feature_vector

__all__ = ["FEATURE_NAMES", "extract_url_features", "feature_vector"]
