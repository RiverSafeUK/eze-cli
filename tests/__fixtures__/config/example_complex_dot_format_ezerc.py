"""fixture"""


def get_expected_python_full_config_object() -> dict:
    """expected python object"""
    return {
        "safety": {"REQUIREMENTS_FILES": ["default-requirements.txt"]},
        "safety_quick": {"REQUIREMENTS_FILES": ["small-requirements.txt"]},
        "safety_slow": {"REQUIREMENTS_FILES": ["big-requirements.txt"]},
        "scan": {
            "ci": {"reporters": ["console"], "tools": ["safety:slow"]},
            "ci-prod": {
                "reporters": ["console"],
                "safety_slow": {"REQUIREMENTS_FILES": ["prod-big-requirements.txt"]},
                "tools": ["safety:slow"],
            },
            "dev": {"reporters": ["console"], "tools": ["safety:fast"]},
            "reporters": ["console", "json", "junit", "quality"],
            "tools": ["safety"],
        },
    }


def get_expected_python_safety() -> dict:
    """expected python object"""
    return {
        "REQUIREMENTS_FILES": ["default-requirements.txt"],
        "quick": {"REQUIREMENTS_FILES": ["small-requirements.txt"]},
        "slow": {"REQUIREMENTS_FILES": ["big-requirements.txt"]},
    }


def get_expected_safety_quick() -> dict:
    """expected python object"""
    return {
        "REQUIREMENTS_FILES": ["small-requirements.txt"],
        "quick": {"REQUIREMENTS_FILES": ["small-requirements.txt"]},
        "slow": {"REQUIREMENTS_FILES": ["big-requirements.txt"]},
    }


def get_expected_dot_safety_slow() -> dict:
    """expected python object"""
    return {
        "REQUIREMENTS_FILES": ["big-requirements.txt"],
        "quick": {"REQUIREMENTS_FILES": ["small-requirements.txt"]},
        "slow": {"REQUIREMENTS_FILES": ["big-requirements.txt"]},
    }
