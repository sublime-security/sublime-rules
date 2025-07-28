"""Sublime Security rule generator for IOK conversions."""

import uuid
from typing import Dict, Any, List, Optional


class SublimeRuleGenerator:
    """Generator for Sublime Security rules from IOK data."""

    def __init__(self):
        self.severity_mapping = {
            'malicious': 'high',
            'suspicious': 'medium',
            'potentially_malicious': 'medium',
            'informational': 'low'
        }

        # IOK field to Sublime MQL field mapping
        self.field_mapping = {
            'html': 'body.html.raw',
            'title': 'subject.subject',
            'hostname': 'sender.email.domain.domain',
            'dom': 'body.html.display_text',
            'js': 'body.links',
            'css': 'body.html.raw',
            'headers': 'headers.hops',
            'cookies': 'headers.hops',
            'requests': 'body.links'
        }

    def generate_rule(self, metadata: Dict[str, Any], patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a Sublime Security rule from IOK metadata and patterns."""

        # Generate MQL source
        mql_source = self._generate_mql(metadata, patterns)

        # Build the rule
        rule = {
            'name': f"IOK: {metadata['title']}",
            'description': self._build_description(metadata),
            'type': 'triage',
            'severity': self.severity_mapping.get(metadata['level'], 'medium'),
            'source': mql_source,
            'attack_types': self._determine_attack_types(metadata),
            'tactics_and_techniques': self._determine_tactics(metadata),
            'detection_methods': self._determine_detection_methods(metadata, patterns),
            'id': str(uuid.uuid4())
        }

        # Add optional fields
        if metadata.get('references'):
            rule['references'] = metadata['references']

        # Add IOK-specific tags
        rule['tags'] = ['IOK_Converted']
        if metadata.get('tags'):
            rule['tags'].extend(metadata["tags"])
        return rule

    def _generate_mql(self, metadata: Dict[str, Any], patterns: List[Dict[str, Any]]) -> str:
        """Generate MQL source code from IOK patterns."""

        conditions = ['type.inbound']

        # Add triage flagged rules condition
        triage_condition = """any(triage.flagged_rules, any(.detection_methods, ..name == "URL analysis"))"""
        conditions.append(triage_condition)

        # Convert IOK patterns to MQL conditions
        for pattern in patterns:
            mql_condition = self._convert_pattern_to_mql(pattern)
            if mql_condition:
                conditions.append(mql_condition)

        # Add brand-specific logic based on metadata
        brand_conditions = self._generate_brand_specific_conditions(metadata)
        if brand_conditions:
            conditions.extend(brand_conditions)

        # Add standard sender filtering
        sender_filter = """(
    not profile.by_sender().solicited
    or (
      profile.by_sender().any_messages_malicious_or_spam
      and not profile.by_sender().any_messages_benign
    )
  )"""
        conditions.append(sender_filter)

        return '\n  and '.join(conditions)

    def _convert_pattern_to_mql(self, pattern: Dict[str, Any]) -> Optional[str]:
        """Convert a single IOK pattern to MQL condition using link analysis for web patterns."""

        field = pattern['field']
        modifier = pattern['modifier']
        operator = pattern.get('operator')
        values = pattern['values']

        # For website-specific patterns (html, dom, js, css), use link analysis
        if field in ['html', 'dom', 'js', 'css', 'requests']:
            return self._convert_web_pattern_to_link_analysis(field, modifier, operator, values)

        # For other fields, map to email equivalents
        sublime_field = self.field_mapping.get(field, field)

        # Handle different modifiers for email fields
        if modifier == 'contains':
            if operator == 'all':
                # All values must be present
                subconditions = []
                for value in values:
                    escaped_value = value.replace('"', '\\"')
                    subconditions.append(f'strings.icontains({sublime_field}, "{escaped_value}")')
                return '(\n    ' + '\n    and '.join(subconditions) + '\n  )'
            else:
                # Any value can be present
                subconditions = []
                for value in values:
                    escaped_value = value.replace('"', '\\"')
                    subconditions.append(f'strings.icontains({sublime_field}, "{escaped_value}")')
                return '(\n    ' + '\n    or '.join(subconditions) + '\n  )'

        elif modifier == 'equals':
            if len(values) == 1:
                escaped_value = values[0].replace('"', '\\"')
                return f'{sublime_field} == "{escaped_value}"'
            else:
                # Fix f-string syntax issue by avoiding nested quotes
                escaped_values = []
                for v in values:
                    escaped_v = v.replace('"', '\\"')
                    escaped_values.append(f'"{escaped_v}"')
                return f'{sublime_field} in ({", ".join(escaped_values)})'

        elif modifier == 'regex':
            if len(values) == 1:
                escaped_value = values[0].replace('"', '\\"')
                return f'regex.icontains({sublime_field}, "{escaped_value}")'

        # Default fallback
        return None

    def _convert_web_pattern_to_link_analysis(self, field: str, modifier: str, operator: Optional[str], values: List[str]) -> str:
        """Convert website-specific IOK patterns to Sublime link analysis."""

        # Use link analysis to check if any linked websites contain the patterns
        if modifier == 'contains' and operator == 'all':
            # All patterns must be found on the linked website's HTML
            subconditions = []
            for value in values:
                escaped_value = value.replace('"', '\\"')
                # TODO: Add logic here to convert href paths to correct escaping. Currently this will take too much time to figure out so skipping as only 2 rules fail because of it
                subconditions.append(f'strings.icontains(ml.link_analysis(.).final_dom.raw, "{escaped_value}")')

            condition_text = '\n    and '.join(subconditions)
            return f"""any(body.links,
    {condition_text}
  )"""

        elif modifier == 'contains':
            # Any pattern can be found on the linked website's HTML
            subconditions = []
            for value in values:
                escaped_value = value.replace('"', '\\"')
                subconditions.append(f'strings.icontains(ml.link_analysis(.).final_dom.raw, "{escaped_value}")')

            condition_text = '\n    or '.join(subconditions)
            return f"""any(body.links,
    {condition_text}
  )"""

        # Default to basic phishing detection
        return """any(body.links,
    ml.link_analysis(.).credphish.disposition == "phishing"
  )"""

    def _generate_brand_specific_conditions(self, metadata: Dict[str, Any]) -> List[str]:
        """Generate brand-specific conditions based on metadata."""

        conditions = []
        title_lower = metadata['title'].lower()
        tags = metadata.get('tags', [])
        tags_str = ' '.join(tags).lower()

        # Brand detection based on title and tags
        if '1password' in title_lower or 'target.1password' in tags_str:
            conditions.append('strings.icontains(subject.subject, "1password")')
            conditions.append('sender.email.domain.domain != "1password.com"')

        elif 'paypal' in title_lower or 'target.paypal' in tags_str:
            conditions.append('strings.icontains(subject.subject, "paypal")')
            conditions.append('sender.email.domain.domain != "paypal.com"')

        elif 'steam' in title_lower or 'target.steam' in tags_str:
            conditions.append('strings.icontains(subject.subject, "steam")')
            conditions.append('sender.email.domain.domain != "steampowered.com"')

        elif 'microsoft' in title_lower or 'office' in title_lower:
            conditions.append('(\n    strings.icontains(subject.subject, "microsoft")\n    or strings.icontains(subject.subject, "office")\n  )')
            conditions.append('sender.email.domain.domain not in ("microsoft.com", "office.com")')

        elif 'amazon' in title_lower:
            conditions.append('strings.icontains(subject.subject, "amazon")')
            conditions.append('sender.email.domain.domain != "amazon.com"')

        elif 'facebook' in title_lower:
            conditions.append('strings.icontains(subject.subject, "facebook")')
            conditions.append('sender.email.domain.domain != "facebook.com"')

        elif 'coinbase' in title_lower or 'crypto' in title_lower:
            conditions.append('(\n    strings.icontains(subject.subject, "coinbase")\n    or strings.icontains(subject.subject, "crypto")\n  )')

        elif 'discord' in title_lower:
            conditions.append('strings.icontains(subject.subject, "discord")')
            conditions.append('sender.email.domain.domain != "discord.com"')

        # Add credential theft detection if no specific brand detected
        if not conditions:
            conditions.append('(\n    strings.icontains(subject.subject, "account")\n    or strings.icontains(subject.subject, "verify")\n    or strings.icontains(subject.subject, "suspended")\n  )')

        return conditions

    def _build_description(self, metadata: Dict[str, Any]) -> str:
        """Build description for the Sublime rule."""

        description = metadata.get('description', 'Converted from IOK rule')
        if description:
            description = description.strip()

        description += "\n\nConverted from IOK rule - original focuses on website analysis."

        return description

    def _determine_attack_types(self, metadata: Dict[str, Any]) -> List[str]:
        """Determine attack types from IOK metadata."""

        attack_types = []
        content = f"{metadata['title']} {' '.join(metadata.get('tags', []))}".lower()

        if any(term in content for term in ['credential', 'phishing', 'login', 'kit']):
            attack_types.append('Credential Phishing')

        if any(term in content for term in ['stealer', 'malware', 'trojan']):
            attack_types.append('Malware/Ransomware')

        if any(term in content for term in ['brand', 'impersonation', 'target.']):
            attack_types.append('Brand Impersonation')

        if any(term in content for term in ['scam', 'fraud', 'drainer']):
            attack_types.append('BEC/Fraud')

        if any(term in content for term in ['crypto', 'bitcoin', 'ethereum']):
            attack_types.append('Cryptocurrency Scam')

        if not attack_types:
            attack_types.append('Credential Phishing')  # Default

        return attack_types

    def _determine_tactics(self, metadata: Dict[str, Any]) -> List[str]:
        """Determine tactics from IOK metadata."""

        tactics = []
        content = f"{metadata['title']} {' '.join(metadata.get('tags', []))}".lower()

        if any(term in content for term in ['impersonation', 'target.', 'brand', 'kit']):
            tactics.append('Impersonation: Brand')

        if any(term in content for term in ['stealer', 'drainer']):
            tactics.append('Malware delivery')

        if any(term in content for term in ['social', 'scam']):
            tactics.append('Social engineering')

        if any(term in content for term in ['crypto', 'giveaway']):
            tactics.append('Investment scam')

        if not tactics:
            tactics.append('Social engineering')  # Default

        return tactics

    def _determine_detection_methods(self, metadata: Dict[str, Any], patterns: List[Dict[str, Any]]) -> List[str]:
        """Determine etection methods from IOK metadata and patterns."""

        methods = ['Content analysis', 'Sender analysis', 'Header analysis']

        # Add specific methods based on patterns
        for pattern in patterns:
            if pattern['field'] in ['html', 'dom', 'js', 'css']:
                methods.append('URL analysis')  # Using link analysis
            elif pattern['field'] in ['requests']:
                methods.append('URL analysis')

        if any(term in metadata['title'].lower() for term in ['credential', 'phishing']):
            methods.append('Natural Language Understanding')

        return list(set(methods))  # Remove duplicates
