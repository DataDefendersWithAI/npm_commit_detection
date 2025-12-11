from .base_config import BaseConfig

class StaticAnalysisConfig(BaseConfig):
    """Configuration for Static Analysis."""
    
    MODEL = BaseConfig.get_env("LLM_MODEL", "gpt-4-turbo")
    CONTEXT_WINDOW = int(BaseConfig.get_env("LLM_CONTEXT_WINDOW", "128000"))
    TEMPERATURE = float(BaseConfig.get_env("LLM_TEMPERATURE", "0"))
