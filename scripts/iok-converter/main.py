#!/usr/bin/env python3
"""CLI script for converting all IOK rules to Sublime format."""

import json
import sys
from pathlib import Path

# Add src to the Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from iok_converter import IOKConverter
    print("✅ Successfully imported IOKConverter")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


def convert_all_iok_rules():
    """Convert all IOK rules to Sublime format."""

    # Path for the IOK rules (will auto-download if needed)
    iok_rules_dir = Path("downloaded_iok_rules")
    output_dir = Path("../../iok-rules")

    # Create converter instance
    converter = IOKConverter()

    print(f"🎯 Target IOK rules directory: {iok_rules_dir}")
    print(f"📁 Output directory: {output_dir}")
    print("-" * 60)

    try:
        # Convert all rules (will auto-download if directory is missing/empty)
        converter.convert_directory(iok_rules_dir, output_dir, auto_download=True)
        return True

    except Exception as e:
        print(f"❌ Conversion failed: {e}")
        return False


def download_only_iok_rules():
    """Download IOK rules without converting them."""
    
    download_dir = Path("downloaded_iok_rules")
    
    # Create converter instance
    converter = IOKConverter()
    
    print(f"📥 Downloading IOK rules to: {download_dir}")
    print("-" * 60)
    
    # Download rules
    success = converter.download_iok_rules(download_dir)
    
    if success:
        rule_count = len(list(download_dir.glob("*.yml")))
        print(f"\n✅ Downloaded {rule_count} IOK rules to {download_dir}/")
    else:
        print(f"❌ Download failed!")
    
    return success


def main():
    """Main function."""
    
    import sys
    
    print("IOK to Sublime Rules Converter")
    print("=" * 60)
    
    # Check for download-only flag
    if len(sys.argv) > 1 and sys.argv[1] == "--download-only":
        print("📥 Download mode: Downloading IOK rules only (no conversion)")
        print("=" * 60)
        success = download_only_iok_rules()
    else:
        print("🔄 Full mode: Download + Convert IOK rules with proper link analysis and YAML formatting")
        print("=" * 60)
        success = convert_all_iok_rules()
    
    if success:
        if len(sys.argv) > 1 and sys.argv[1] == "--download-only":
            print(f"\n🎉 IOK rules downloaded successfully!")
        else:
            print(f"\n🎉 All IOK rules converted successfully!")
            print(f"Check the 'converted_sublime_rules_final' directory for results.")
    else:
        print(f"❌ Operation failed!")
    
    # Usage instructions
    print(f"\nUsage:")
    print(f"  python main.py                # Download + convert all IOK rules")
    print(f"  python main.py --download-only # Download IOK rules only (no conversion)")


if __name__ == "__main__":
    main() 