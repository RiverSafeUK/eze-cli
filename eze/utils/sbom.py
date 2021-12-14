from eze.core.enums import Vulnerability

LICENSE_GROUPS = {
    "COPYLEFT" :
}


DEFAULT_POLICY = {
    "license_groups": {
        "proprietary": [

        ],
        "copyleft": [

        ],
        "weakcopyleft": [

        ]
    },
    "policies": [
        {
            "severity": "high",
            "licenses": [],
            "license_groups": ["copyleft"]
        }
    ]
}


def check_licenses(sbom: dict, license_policy: dict = None) -> list:
    """check licenses for violations of policies"""
    return []
