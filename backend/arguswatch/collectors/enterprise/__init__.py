"""Enterprise collectors - architecture wired, key-activated.
Each collector checks for its API key at startup.
Key present -> collector loads and runs.
Key absent -> silent skip, no errors.
"""
