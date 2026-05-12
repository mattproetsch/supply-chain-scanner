__version__ = "0.1.0"

# Overridden at bundle time by build.py with the actual UTC build timestamp.
# When running from source, this stays as None so the report shows "(source)".
BUILD_TS: str | None = None

