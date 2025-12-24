from .base_config import BaseConfig

class VerificationConfig(BaseConfig):
    # Use simple verification instead of advanced verification
    _use_simple_verification: bool = True