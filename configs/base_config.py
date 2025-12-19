import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
# override=False means existing env vars take precedence over .env values
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env", override=False)

class BaseConfig:
    """Base configuration class."""
    # Add common configuration here
    BASE_DIR = BASE_DIR
    
    @staticmethod
    def get_env(key: str, default: str = None) -> str:
        """Get environment variable - checks machine env first, then .env, then default"""
        return os.getenv(key, default)
