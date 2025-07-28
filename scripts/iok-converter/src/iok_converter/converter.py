"""Main IOK to Sublime converter class."""

import zipfile
from io import BytesIO
from pathlib import Path
from typing import Dict, Any, Union

import yaml
import requests

from .parser import IOKParser
from .generator import SublimeRuleGenerator


class IOKConverter:
    """Main converter class for IOK to Sublime Security rules."""

    def __init__(self):
        self.parser = IOKParser()
        self.generator = SublimeRuleGenerator()
        self.stats = {
            'total_rules': 0,
            'successful_conversions': 0,
            'failed_conversions': 0,
            'errors': []
        }

    def convert_file(self, input_file: Union[str, Path], output_dir: Union[str, Path] = None) -> Dict[str, Any]:
        """Convert a single IOK file to Sublime rule."""

        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        try:
            # Parse the IOK rule
            rule_data = self.parser.parse_file(str(input_path))
            metadata = self.parser.extract_metadata(rule_data)
            patterns = self.parser.extract_detection_patterns(rule_data)

            # Generate the Sublime rule
            sublime_rule = self.generator.generate_rule(metadata, patterns)

            # Save if output directory specified
            if output_dir:
                self._save_rule(sublime_rule, input_path.stem, output_dir)

            return sublime_rule

        except Exception as e:
            self.stats['errors'].append(f"Error converting {input_file}: {e}")
            raise

    def download_iok_rules(self, download_dir: Union[str, Path] = "downloaded_iok_rules", **kwargs: Any) -> str:
        """Download IOK rules from the GitHub repository."""
        URL: str = "https://github.com/phish-report/IOK/zipball/main/"
        response = requests.get(url=URL, stream=True)
        response.raise_for_status()
        download_path = Path(download_dir)
        download_path.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(BytesIO(response.content)) as zf:
            for member in zf.infolist():
                if "/indicators/" in member.filename and member.filename.endswith(('.yml', '.yaml')):
                    # Extract just the filename without the directory structure
                    filename = Path(member.filename).name
                    if filename:  # Skip directories
                        # Extract the file content and save it directly to the download folder
                        file_content = zf.read(member)
                        output_file = download_path / filename
                        with open(output_file, 'wb') as f:
                            f.write(file_content)
        return download_path

    def convert_directory(self, input_dir: Union[str, Path] = Path("downloaded_iok_rules"), output_dir: Union[str, Path] = Path("../../iok-rules"), auto_download: bool = True) -> None:
        """Convert all IOK files in a directory."""

        input_path = Path(input_dir)
        output_path = Path(output_dir)

        # Auto-download if directory doesn't exist or is empty
        if auto_download and (not input_path.exists() or len(list(input_path.glob("*.yml"))) == 0):
            print(f"📂 IOK rules directory not found or empty: {input_path}")
            if self.download_iok_rules(input_path):
                print(f"✅ IOK rules downloaded to {input_path}")
            else:
                raise FileNotFoundError(f"Failed to download IOK rules to {input_path}")

        if not input_path.exists():
            raise FileNotFoundError(f"Input directory not found: {input_dir}")

        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)

        # Find all IOK files
        iok_files = list(input_path.glob("*.yml")) + list(input_path.glob("*.yaml"))

        if not iok_files:
            print(f"No IOK files found in {input_dir}")
            return

        self.stats['total_rules'] = len(iok_files)
        print(f"🔄 Converting {len(iok_files)} IOK files...")

        # Convert each file
        for i, iok_file in enumerate(iok_files):
            try:
                sublime_rule = self.convert_file(iok_file, output_path)
                self.stats['successful_conversions'] += 1

                # Progress update
                if (i + 1) % 25 == 0:
                    print(f"Processed {i + 1}/{len(iok_files)} files...")

            except Exception as e:
                self.stats['failed_conversions'] += 1
                self.stats['errors'].append(f"Failed to convert {iok_file.name}: {e}")
                print(f"Error converting {iok_file.name}: {e}")

        # Print final statistics
        self._print_stats()

    def _save_rule(self, rule: Dict[str, Any], base_name: str, output_dir: Union[str, Path]) -> None:
        """Save a rule in YAML format with proper source formatting."""

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Clean the base name for file naming
        safe_name = "".join(c for c in base_name if c.isalnum() or c in ('-', '_'))

        # Save as YAML with proper source formatting
        yaml_file = output_path / f"{safe_name}.yml"
        with open(yaml_file, 'w', encoding='utf-8') as f:
            self._write_yaml_with_literal_source(rule, f)

    def _write_yaml_with_literal_source(self, rule: Dict[str, Any], file) -> None:
        """Write YAML with proper literal block formatting for the source field."""

        # Make a copy to avoid modifying the original
        rule_copy = rule.copy()
        source = rule_copy.pop('source', '')

        # Write all fields except source using standard YAML
        yaml.dump(rule_copy, file, default_flow_style=False, allow_unicode=True, indent=2)

        # Write source field as literal block at the end
        if source:
            file.write('source: |\n')
            for line in source.split('\n'):
                file.write(f'  {line}\n')

    def _print_stats(self) -> None:
        """Print conversion statistics."""

        print(f"\n{'='*60}")
        print(f"CONVERSION COMPLETED")
        print(f"{'='*60}")
        print(f"Total IOK rules processed: {self.stats['total_rules']}")
        print(f"Successful conversions: {self.stats['successful_conversions']}")
        print(f"Failed conversions: {self.stats['failed_conversions']}")

        if self.stats['total_rules'] > 0:
            success_rate = (self.stats['successful_conversions'] / self.stats['total_rules']) * 100
            print(f"Success rate: {success_rate:.1f}%")

        if self.stats['errors']:
            print(f"\nFirst 5 errors:")
            for error in self.stats['errors'][:5]:
                print(f"  - {error}")
            if len(self.stats['errors']) > 5:
                print(f"  ... and {len(self.stats['errors']) - 5} more errors")

    def test_single_rule(self, rule_content: str) -> Dict[str, Any]:
        """Test conversion of a single rule from content string."""

        try:
            # Parse the rule
            rule_data = self.parser.parse_content(rule_content)
            metadata = self.parser.extract_metadata(rule_data)
            patterns = self.parser.extract_detection_patterns(rule_data)

            # Generate the Sublime rule
            sublime_rule = self.generator.generate_rule(metadata, patterns)

            return {
                'success': True,
                'rule': sublime_rule,
                'metadata': metadata,
                'patterns': patterns
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
