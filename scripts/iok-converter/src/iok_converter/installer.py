#!/usr/bin/env python3
"""
Creates automations for generated iok-rules

A Python client for creating automation rules rules within the Sublime platform.
"""

import logging
from dataclasses import dataclass
from typing import Dict
from pathlib import Path

import requests
import yaml


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class AutomationRule:
    """Represents a single automation rule"""
    name: str
    description: str
    source: str
    tags: list[str]
    severity: str
    type: str = "triage"
    auto_review_auto_share: bool = False
    active: bool = True
    triage_abuse_reports: bool = False
    triage_flagged_messages: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "tags": self.tags,
            "type": self.type,
            "auto_review_auto_share": self.auto_review_auto_share,
            "active": self.active,
            "severity": self.severity,
            "triage_abuse_reports": self.triage_abuse_reports,
            "triage_flagged_messages": self.triage_flagged_messages
        }


class AutomationClient:
    """Client for creating automation rules via API"""

    def __init__(self):
        """
        Initialize the client
        """
        self.rules: list[AutomationRule] = []

    def _load_all_rules(self, rule_path: str = "../../iok-rules") -> None:
        self.rule_path = Path(rule_path)
        for item in self.rule_path.iterdir():
            rule = self._parse_automation_rule(item)
            if rule:
                self.rules.append(rule)

    def _load_yaml(self, file_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"file not found: {file_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file: {e}")
            raise

    def _parse_automation_rule(self, path: str) -> AutomationRule:
        data = self._load_yaml(path)
        if data:
            return AutomationRule(
                name=data.get("name"),
                description=data.get("description"),
                source=data.get("source"),
                tags=data.get("tags", []),
                severity=data.get("severity", "")
            )
        return None

    def upload_automations(self, token: str, url: str = "https://platform.sublime.security/v1/rules", input_directory: str | Path = "../../iok-rules") -> bool:
        self._load_all_rules(rule_path=input_directory)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        return_value: bool = False
        for rule in self.rules:
            payload: dict = rule.to_dict()
            resp = requests.post(
                url=url,
                json=payload,
                headers=headers,
            )
            if not resp.ok:
                return_value = False
                print(f"failed processing rule {resp.text}")
            else:
                return_value = True
        return return_value
