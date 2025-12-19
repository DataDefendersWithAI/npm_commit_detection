from .base_config import BaseConfig

class StaticAnalysisConfig(BaseConfig):
    """Configuration for Static Analysis."""
    
    MODEL = BaseConfig.get_env("LLM_MODEL", "gpt-4-turbo")
    
    # Handle empty string values with fallback
    _context_window = BaseConfig.get_env("LLM_CONTEXT_WINDOW", "128000")
    CONTEXT_WINDOW = int(_context_window) if _context_window else 128000
    
    _temperature = BaseConfig.get_env("LLM_TEMPERATURE", "0")
    TEMPERATURE = float(_temperature) if _temperature else 0.0
