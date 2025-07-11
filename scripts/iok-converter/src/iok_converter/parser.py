"""IOK rule parser using PyYAML for proper YAML handling."""

import yaml
from typing import Dict, Any, List


class IOKParser:
    """Parser for IOK (Indicator of Kit) rules."""
    
    def __init__(self):
        self.loader = yaml.SafeLoader
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse an IOK rule file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return self.parse_content(content)
        except Exception as e:
            raise IOKParseError(f"Failed to parse {file_path}: {e}")
    
    def parse_content(self, content: str) -> Dict[str, Any]:
        """Parse IOK rule content."""
        try:
            # Use PyYAML for proper YAML parsing
            rule_data = yaml.safe_load(content)
            if not rule_data:
                raise IOKParseError("Empty or invalid YAML content")
            
            # Validate required fields
            if 'title' not in rule_data:
                raise IOKParseError("Missing required field 'title'")
            
            return rule_data
        except yaml.YAMLError as e:
            raise IOKParseError(f"YAML parsing error: {e}")
        except Exception as e:
            raise IOKParseError(f"Unexpected error: {e}")
    
    def extract_detection_patterns(self, rule_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract detection patterns from IOK rule data."""
        patterns = []
        
        detection = rule_data.get('detection', {})
        if not detection:
            return patterns
        
        # Extract condition
        condition = detection.get('condition', '')
        
        # Extract detection rules
        for rule_name, rule_content in detection.items():
            if rule_name == 'condition':
                continue
            
            if isinstance(rule_content, dict):
                for field_pattern, values in rule_content.items():
                    # Parse field|modifier|operator patterns
                    parts = field_pattern.split('|')
                    if len(parts) >= 2:
                        field = parts[0]
                        modifier = parts[1]
                        operator = parts[2] if len(parts) > 2 else None
                        
                        patterns.append({
                            'rule_name': rule_name,
                            'field': field,
                            'modifier': modifier,
                            'operator': operator,
                            'values': values if isinstance(values, list) else [values]
                        })
        
        return patterns
    
    def extract_metadata(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from IOK rule data."""
        return {
            'title': rule_data.get('title', ''),
            'description': rule_data.get('description', ''),
            'references': rule_data.get('references', []),
            'level': rule_data.get('level', 'malicious'),
            'tags': rule_data.get('tags', []),
            'author': rule_data.get('author', ''),
            'date': rule_data.get('date', ''),
            'id': rule_data.get('id', '')
        }


class IOKParseError(Exception):
    """Exception raised when IOK parsing fails."""
    pass
