#!/usr/bin/env python3
"""
JSON Sanitizer Script
Removes null values, personal sensitive information, and allows manual removal of keys/keywords.
"""

import json
import sys
import re
from typing import Dict, List, Any, Set
from pathlib import Path

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False
    print("Warning: presidio-analyzer and presidio-anonymizer not installed.")
    print("Install with: pip install presidio-analyzer presidio-anonymizer")
    print("Falling back to regex-based PII detection.\n")


class JSONSanitizer:
    """Sanitizes JSON data by removing nulls, PII, and user-specified keys/keywords."""
    
    def __init__(self):
        self.analyzer = None
        self.anonymizer = None
        if PRESIDIO_AVAILABLE:
            try:
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
            except Exception as e:
                print(f"Warning: Could not initialize Presidio: {e}")
                print("Falling back to regex-based PII detection.\n")
    
    def remove_nulls(self, data: Any, remove_empty_strings: bool = True, remove_empty_arrays: bool = True) -> Any:
        """Recursively remove all key-value pairs with null values and null items from arrays."""
        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                if v is not None:
                    processed_value = self.remove_nulls(v, remove_empty_strings, remove_empty_arrays)
                    # Only add if value is not None after processing
                    if processed_value is not None:
                        # Skip empty strings if requested
                        if remove_empty_strings and isinstance(processed_value, str) and processed_value == "":
                            continue
                        # Skip empty arrays if requested
                        if remove_empty_arrays and isinstance(processed_value, list) and len(processed_value) == 0:
                            continue
                        result[k] = processed_value
            return result
        elif isinstance(data, list):
            result = []
            for item in data:
                if item is not None:
                    processed_item = self.remove_nulls(item, remove_empty_strings, remove_empty_arrays)
                    # Only add if item is not None after processing
                    if processed_item is not None:
                        # Skip empty strings if requested
                        if remove_empty_strings and isinstance(processed_item, str) and processed_item == "":
                            continue
                        # Skip empty arrays if requested
                        if remove_empty_arrays and isinstance(processed_item, list) and len(processed_item) == 0:
                            continue
                        result.append(processed_item)
            return result
        else:
            return data
    
    def detect_pii_regex(self, text: str) -> List[Dict[str, Any]]:
        """Detect PII using regex patterns when Presidio is not available."""
        patterns = [
            # Email
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL_ADDRESS'),
            # Phone numbers (US format)
            (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'PHONE_NUMBER'),
            # SSN
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
            # Credit card (basic pattern)
            (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'CREDIT_CARD'),
            # IP address
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP_ADDRESS'),
        ]
        
        entities = []
        for pattern, entity_type in patterns:
            for match in re.finditer(pattern, text):
                entities.append({
                    'entity_type': entity_type,
                    'start': match.start(),
                    'end': match.end(),
                    'score': 0.9
                })
        return entities
    
    def anonymize_text(self, text: str) -> str:
        """Anonymize sensitive information in text."""
        if not text or not isinstance(text, str):
            return text
        
        if self.analyzer and self.anonymizer:
            try:
                # Detect PII using Presidio
                results = self.analyzer.analyze(text=text, language='en')
                if results:
                    # Anonymize the detected entities
                    anonymized = self.anonymizer.anonymize(
                        text=text,
                        analyzer_results=results
                    )
                    return anonymized.text
            except Exception as e:
                print(f"Warning: Presidio error: {e}, using regex fallback")
        
        # Fallback to regex-based detection
        entities = self.detect_pii_regex(text)
        if entities:
            # Sort by start position (descending) to replace from end to start
            entities.sort(key=lambda x: x['start'], reverse=True)
            anonymized_text = text
            for entity in entities:
                start = entity['start']
                end = entity['end']
                entity_type = entity['entity_type']
                # Replace with generic placeholder
                placeholder = f"[{entity_type}_REDACTED]"
                anonymized_text = anonymized_text[:start] + placeholder + anonymized_text[end:]
            return anonymized_text
        
        return text
    
    def remove_sensitive_info(self, data: Any) -> Any:
        """Recursively remove sensitive information from JSON data."""
        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                # Check if key suggests sensitive information
                sensitive_keywords = ['password', 'passwd', 'secret', 'token', 'api_key', 
                                    'ssn', 'social_security', 'credit_card', 'card_number',
                                    'email', 'phone', 'address', 'name', 'dob', 'birth_date']
                key_lower = k.lower()
                
                if any(keyword in key_lower for keyword in sensitive_keywords):
                    # Remove the entire key-value pair
                    continue
                
                # Recursively process value
                result[k] = self.remove_sensitive_info(v)
            
            # Also anonymize string values
            for k, v in result.items():
                if isinstance(v, str):
                    result[k] = self.anonymize_text(v)
            
            return result
        elif isinstance(data, list):
            return [self.remove_sensitive_info(item) for item in data]
        elif isinstance(data, str):
            return self.anonymize_text(data)
        else:
            return data
    
    def remove_keywords(self, data: Any, keywords: Set[str]) -> Any:
        """Remove entries containing specified keywords in keys or values."""
        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                # Check if key contains any keyword
                if any(keyword.lower() in k.lower() for keyword in keywords):
                    continue
                
                # Process value
                processed_value = self.remove_keywords(v, keywords)
                
                # Check if value contains keyword (for strings)
                if isinstance(processed_value, str):
                    if any(keyword.lower() in processed_value.lower() for keyword in keywords):
                        continue
                
                result[k] = processed_value
            return result
        elif isinstance(data, list):
            return [self.remove_keywords(item, keywords) for item in data if item is not None]
        elif isinstance(data, str):
            # Check if string contains keyword
            if any(keyword.lower() in data.lower() for keyword in keywords):
                return None
            return data
        else:
            return data
    
    def remove_keys(self, data: Any, keys_to_remove: Set[str], root_level: bool = True) -> Any:
        """Remove specified keys from JSON objects.
        
        Args:
            data: JSON data to process
            keys_to_remove: Set of keys to remove
            root_level: If True, only remove keys at root level (not nested)
        """
        if isinstance(data, dict):
            if root_level:
                # Only remove keys at the current (root) level
                return {
                    k: self.remove_keys(v, keys_to_remove, root_level=False)
                    for k, v in data.items()
                    if k not in keys_to_remove
                }
            else:
                # Recursively process nested structures without removing keys
                return {
                    k: self.remove_keys(v, keys_to_remove, root_level=False)
                    for k, v in data.items()
                }
        elif isinstance(data, list):
            # When at root level, each item in the list should also have root-level keys removed
            # When not at root level, process nested items without removing keys
            return [self.remove_keys(item, keys_to_remove, root_level=root_level) for item in data]
        else:
            return data
    
    def sanitize(self, data: Any, remove_nulls: bool = True, 
                 remove_pii: bool = True, keywords: Set[str] = None, 
                 keys_to_remove: Set[str] = None) -> Any:
        """Apply all sanitization steps."""
        result = data
        
        if remove_nulls:
            result = self.remove_nulls(result)
        
        if remove_pii:
            result = self.remove_sensitive_info(result)
        
        if keywords:
            result = self.remove_keywords(result, keywords)
            # Remove nulls again after keyword removal
            result = self.remove_nulls(result)
        
        if keys_to_remove:
            result = self.remove_keys(result, keys_to_remove, root_level=True)
            # Remove nulls again after key removal
            result = self.remove_nulls(result)
        
        return result


def load_json_file(filepath: str) -> Any:
    """Load JSON from file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file: {e}")
        sys.exit(1)


def json_to_markdown(data: Any) -> str:
    """Convert JSON data to Markdown format."""
    lines = []
    
    if isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict):
                lines.append(f"\n## Record {i + 1}\n")
                
                # Create a table for key-value pairs
                for key, value in item.items():
                    if isinstance(value, list):
                        if value:  # Only add if list is not empty
                            items_str = ", ".join(str(v) for v in value if v is not None and str(v).strip())
                            if items_str:
                                lines.append(f"- **{key}**: {items_str}")
                    elif isinstance(value, dict):
                        lines.append(f"- **{key}**:")
                        for k, v in value.items():
                            lines.append(f"  - {k}: {v}")
                    else:
                        if value is not None and str(value).strip():
                            lines.append(f"- **{key}**: {value}")
                lines.append("")  # Empty line between records
    elif isinstance(data, dict):
        lines.append("## Record\n")
        for key, value in data.items():
            if isinstance(value, list):
                if value:
                    items_str = ", ".join(str(v) for v in value if v is not None and str(v).strip())
                    if items_str:
                        lines.append(f"- **{key}**: {items_str}")
            elif isinstance(value, dict):
                lines.append(f"- **{key}**:")
                for k, v in value.items():
                    lines.append(f"  - {k}: {v}")
            else:
                if value is not None and str(value).strip():
                    lines.append(f"- **{key}**: {value}")
    else:
        lines.append(str(data))
    
    return "\n".join(lines)


def save_plain_text_file(data: Any, filepath: str):
    """Save JSON data as Markdown file."""
    try:
        # Convert to markdown format
        markdown_content = json_to_markdown(data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        print(f"✓ Results saved to '{filepath}'")
        print(f"✓ Markdown file created (size: {len(markdown_content)} characters)")
    except Exception as e:
        print(f"Error saving file: {e}")
        sys.exit(1)


def main():
    """Main function to run the JSON sanitizer."""
    if len(sys.argv) < 2:
        print("Usage: python3 json_sanitizer.py <input_json_file>")
        print("\nExample:")
        print("  python3 json_sanitizer.py input.json")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Auto-generate output filename based on input filename
    input_path = Path(input_file)
    output_file = input_path.stem + "_sanitized.md"
    
    print(f"Loading JSON from '{input_file}'...")
    data = load_json_file(input_file)
    
    sanitizer = JSONSanitizer()
    
    # Automatically remove nulls, empty strings, and empty arrays (for Neo4j compatibility)
    print("Removing null values, empty strings, and empty arrays...")
    data = sanitizer.remove_nulls(data, remove_empty_strings=True, remove_empty_arrays=True)
    
    # Automatically remove specified keys: email, mobileNumber, bloodGroup, created, lastModified
    keys_to_remove = {'email', 'mobileNumber', 'bloodGroup', 'created', 'lastModified'}
    print(f"Removing root-level keys: {', '.join(sorted(keys_to_remove))}...")
    data = sanitizer.remove_keys(data, keys_to_remove, root_level=True)
    
    # Remove nulls again after key removal
    data = sanitizer.remove_nulls(data, remove_empty_strings=True, remove_empty_arrays=True)
    
    # Validate JSON structure
    print("Validating JSON structure...")
    try:
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        json.loads(json_str)  # Verify it can be parsed
        print(f"✓ JSON is valid (size: {len(json_str)} characters)")
    except Exception as e:
        print(f"⚠ Warning: JSON validation issue: {e}")
    
    # Save as plain text
    print(f"Saving results to '{output_file}'...")
    save_plain_text_file(data, output_file)
    
    print("\n✓ Sanitization complete!")
    print(f"Final output saved to '{output_file}'")


if __name__ == "__main__":
    main()

