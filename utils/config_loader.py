"""
Configuration loader utility
"""

import os
import re
import yaml
from pathlib import Path
from typing import Dict, Any
from utils.logger import get_logger

logger = get_logger(__name__)


class ConfigLoader:
    """Load and manage configuration."""

    @staticmethod
    def load(config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to configuration file

        Returns:
            Configuration dictionary
        """
        config_file = Path(config_path)

        if not config_file.exists():
            logger.warning(f"Config file not found: {config_path}")
            return ConfigLoader._get_default_config()

        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)

            # Substitute environment variables
            config = ConfigLoader._substitute_env_vars(config)

            logger.info(f"Configuration loaded from {config_path}")
            return config

        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return ConfigLoader._get_default_config()

    @staticmethod
    def _substitute_env_vars(obj):
        """
        Recursively substitute ${ENV_VAR} and ${ENV_VAR:-default} patterns
        with environment variable values.
        """
        if isinstance(obj, str):
            pattern = re.compile(r'\$\{([^}:]+)(?::-([^}]*))?\}')
            def replacer(match):
                var_name = match.group(1)
                default = match.group(2) if match.group(2) is not None else match.group(0)
                return os.environ.get(var_name, default)
            return pattern.sub(replacer, obj)
        elif isinstance(obj, dict):
            return {k: ConfigLoader._substitute_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [ConfigLoader._substitute_env_vars(item) for item in obj]
        return obj
    
    @staticmethod
    def _get_default_config() -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'ai_providers': {
                'openai': {
                    'enabled': False,
                    'model': 'gpt-4o',
                    'temperature': 0.7,
                    'max_tokens': 2000
                }
            },
            'scanner': {
                'default_threads': 5,
                'default_depth': 2,
                'timeout': 10,
                'user_agent': 'Deep-Eye/1.0'
            },
            'vulnerability_scanner': {
                'enabled_checks': [
                    'sql_injection',
                    'xss',
                    'command_injection',
                    'ssrf',
                    'xxe',
                    'path_traversal',
                    'csrf',
                    'open_redirect',
                    'cors_misconfiguration',
                    'security_misconfiguration'
                ],
                'payload_generation': {
                    'use_ai': False
                }
            },
            'reconnaissance': {
                'enabled_modules': []
            },
            'reporting': {
                'default_format': 'html'
            },
            'logging': {
                'level': 'INFO'
            }
        }
