# Project-2
Extending the JWKS server

Please ensure all necessary libraries are installed in your venv folder before running:
- Flask
- PyJWT
- Cryptography
- sqlite3 (included in Python standard library)

After creating and activating your virtual environment, enter:
pip install Flask PyJWT cryptography

The server can now be started using "python server.py"

To run the test suite, install these additional libraries:
- pytest
- requests
- pytest-cov (for coverage)

pip install pytest requests pytest-cov

To run the test suite with coverage, use:
pytest --cov=server test_server.py --cov-report=term-missing
