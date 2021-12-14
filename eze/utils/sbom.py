import os
from pathlib import Path

import re
from pydash import py_

from eze.core.enums import Vulnerability, Component
from eze.utils.io import load_json
from eze.utils.log import log_error

DEFAULT_PROPRIETARY_POLICY = {
    "type": {
        "error": ["proprietary", "source-available", "noncommercial", "copyleft"],
        "warn": ["permissive-with-conditions"],
    },
    "licenses": {"error": [], "warn": []},
    "warn_non_opensource_licenses": False,
    "warn_unprofessional_licenses": True,
    "warn_deprecated_licenses": True,
}

DEFAULT_PERMISSIVE_POLICY = {
    "type": {"error": ["proprietary", "copyleft"], "warn": ["permissive-with-conditions"]},
    "licenses": {"error": [], "warn": []},
    "warn_non_opensource_licenses": False,
    "warn_unprofessional_licenses": True,
    "warn_deprecated_licenses": True,
}

DEFAULT_OPENSOURCE_POLICY = {
    "type": {"error": ["proprietary"], "warn": ["permissive-with-conditions"]},
    "licenses": {"error": [], "warn": []},
    "warn_non_opensource_licenses": True,
    "warn_unprofessional_licenses": True,
    "warn_deprecated_licenses": True,
}


class Cache:
    """Cache class container"""


__c = Cache()
__c.licenses_data = None


def get_licenses_data() -> dict:
    """get license data from eze/data/spdx-license-list-data-supplement.json"""
    if not __c.licenses_data:
        file_dir = os.path.dirname(__file__)
        fixture_path = Path(file_dir) / ".." / "data" / "spdx-license-list-data-supplement.json"
        __c.licenses_data = load_json(fixture_path)
    return __c.licenses_data


def normalise_license_id(license_text: str) -> str:
    """normalise license id"""

    def _normalise_license_id(matches):
        return matches.group(1) + "-" + matches.group(2)

    return re.sub("^\\s*([a-zA-Z]+)[- _]+([0-9]+(?:[.][0-9.]+)?)\\s*$", _normalise_license_id, license_text)


def get_bom_license(license_dict: dict) -> str:
    """Parse cyclonedx license object for normalised license"""
    license_text = py_.get(license_dict, "license.name")
    if not license_text:
        license_text = py_.get(license_dict, "license.id")
    if license_text:
        # normalise upper and lower case unknown entries
        if license_text.lower() == "unknown":
            license_text = "unknown"
    return license_text


def get_license(license_text: str) -> dict:
    """get license data from eze/data/spdx-license-list-data-supplement.json"""
    licenses_data = get_licenses_data()

    # by spdx short code
    license_id = normalise_license_id(license_text)
    if license_id in licenses_data["licenses"]:
        return licenses_data["licenses"][license_id]
    # by name
    for key in licenses_data["licenses"]:
        license_data = licenses_data["licenses"][key]
        if license_text == license_data["name"]:
            return license_data
    # by pattern
    for license_pattern in licenses_data["licensesPatterns"]:
        license_data = licenses_data["licensesPatterns"][license_pattern]
        if re.match(license_pattern, license_text):
            created_license_data = license_data.copy()
            created_license_data["id"] = license_text
            created_license_data["isOsiApproved"] = None
            created_license_data["isFsfLibre"] = None
            created_license_data["isDeprecated"] = None
            return created_license_data
    return None


def annotate_licenses(sbom: dict) -> list:
    """adding annotations to licenses for violations of policies"""
    sbom_components = []
    for component in sbom["components"]:
        # manual parsing for name and id
        component_name = component["name"]
        component_group = component.get("group")
        if component_group:
            component_name = f"{component_group}.{component_name}"

        # manual parsing for license
        licenses = component.get("licenses", [])
        license_id = None
        if licenses and len(licenses) > 0:
            license_texts = []
            for license_obj in licenses:
                license_id = get_bom_license(license_obj)
                if license_id:
                    license_texts.append(license_id)
            if len(license_texts) > 1:
                log_error(
                    f"found multiple licenses for component '{component_name}', licenses: '{', '.join(license_texts)}', using '{license_id}'"
                )
        sbom_component = Component(
            {
                "type": component["type"],
                "name": component_name,
                "version": component["version"],
                "license": license_id,
                "description": component.get("description", ""),
            }
        )
        if not license_id:
            license_id = "unknown"
        license_data = get_license(license_id)
        if license_data:
            sbom_component.license = license_data["id"]
            sbom_component.license_type = license_data["type"]
            sbom_component.license_is_professional = license_data["isProfessional"]
            sbom_component.license_is_osi_approved = license_data["isOsiApproved"]
            sbom_component.license_is_fsf_libre = license_data["isFsfLibre"]
            sbom_component.license_is_deprecated = license_data["isDeprecated"]
        sbom_components.append(sbom_component)
    return sbom_components


def check_licenses(sbom: dict, license_policy: str = dict) -> list:
    """check licenses for violations of policies"""
    return []
