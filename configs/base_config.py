import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
# Assuming .env is in the root of the project, which is one level up from this file
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class BaseConfig:
    """Base configuration class."""
    # Add common configuration here
    BASE_DIR = BASE_DIR
    
    @staticmethod
    def get_env(key: str, default: str = None) -> str:
        return os.getenv(key, default)
