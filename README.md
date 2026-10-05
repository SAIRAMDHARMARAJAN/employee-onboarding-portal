# Employee Onboarding Portal

A Streamlit employee onboarding portal with separate HR and Employee portals backed by Snowflake.

## Setup

1. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Copy `.env.example` to `.env` and configure the Snowflake connection and HR password.

3. Place the Snowflake private key at the configured path.

## Run

```bash
streamlit run employee_onboarding_portal.py
```

The `.env` file and private-key files are ignored by Git and must not be committed.
