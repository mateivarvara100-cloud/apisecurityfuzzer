# Python runs this file when you type `python -m apifuzz`. It does the same thing as the
# `apifuzz` command: hand control to the CLI app defined in cli.py.
from apifuzz.cli import app

app(prog_name="apifuzz")  # prog_name makes help text say "apifuzz" instead of "__main__.py"
