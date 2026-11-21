"""The app uvicorn serves, built from the environment: `uvicorn apifuzz_web.main:app`."""

import logging

from apifuzz_web.app import create_app

logging.basicConfig(level=logging.INFO)
app = create_app()
