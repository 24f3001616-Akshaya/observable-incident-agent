import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
raw_db = os.getenv("DATABASE_PATH", "incident_agent.sqlite3")
if os.path.isabs(raw_db):
    DB_PATH = raw_db
else:
    DB_PATH = os.path.join(APP_DIR, raw_db)

PROFILE = "ga5-incident-agent/v2"

OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
MODEL_NAME = os.getenv("MODEL_NAME", "openai/gpt-4o-mini")

# Maximum payload size (bytes) - default 1MB
MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", 1024 * 1024))
