from .base_config import BaseConfig

class DynamicAnalysisConfig(BaseConfig):
    """Configuration for Dynamic Analysis."""
    
    # Server configuration
    SERVER_URL = BaseConfig.get_env("PACKAGE_HUNTER_URL", "http://localhost:3000")
    
    # Timeout configuration
    MAX_WAIT_TIME = int(BaseConfig.get_env("DYNAMIC_WAIT_TIME", "300"))
    POLL_INTERVAL = int(BaseConfig.get_env("POLL_INTERVAL", "5"))
    
    # Execution configuration
    SKIP_DYNAMIC = BaseConfig.get_env("SKIP_DYNAMIC", "false").lower() == "true"
