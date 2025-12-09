# JSON Sanitizer

A Python script to sanitize JSON files by removing null values, personal sensitive information, and allowing manual removal of keys/keywords.

## Features

- ✅ **Automatically removes null values** from all JSON entries
- ✅ **Automatically detects and removes sensitive information** (PII) using Presidio library or regex fallback
- ✅ **Interactive keyword removal** - remove entries containing specific keywords
- ✅ **Interactive key removal** - remove specific JSON keys
- ✅ **Iterative workflow** - make multiple passes until satisfied
- ✅ **Saves results after each step** to the output JSON file

## Installation

1. Install required dependencies:
```bash
pip3 install -r requirements.txt
```

Or install manually:
```bash
pip3 install presidio-analyzer presidio-anonymizer
```

**Note:** If Presidio is not installed, the script will fall back to regex-based PII detection.

## Usage

```bash
python3 json_sanitizer.py <input_json_file> [output_json_file]
```

### Examples

```bash
# Use default output filename (sanitized_output.json)
python3 json_sanitizer.py data.json

# Specify custom output filename
python3 json_sanitizer.py data.json cleaned_data.json
```

## Workflow

1. **Automatic Sanitization**: The script automatically:
   - Removes all key-value pairs with `null` values
   - Detects and removes sensitive information (emails, phone numbers, SSN, credit cards, etc.)
   - Removes keys that suggest sensitive data (password, secret, token, etc.)

2. **Interactive Keyword Removal**: 
   - Enter comma-separated keywords
   - Any keys or values containing these keywords will be removed
   - Press Enter to skip

3. **Interactive Key Removal**:
   - Enter comma-separated JSON keys to remove
   - Press Enter to skip

4. **Iterate**: After each step, the script asks if you're satisfied
   - Answer `yes` or `y` to exit
   - Answer `no` or press Enter to continue with another iteration

## Example Session

```
$ python3 json_sanitizer.py input.json output.json
Loading JSON from 'input.json'...

============================================================
Step 1: Automatically removing null values and sensitive information...
============================================================
✓ Results saved to 'output.json'

============================================================
Iteration 1
============================================================

--- Remove by Keywords ---
Enter comma-separated keywords to remove (keys or values containing these will be removed).
Press Enter to skip this step.
Keywords: internal, debug

Removing entries containing keywords: internal, debug
✓ Results saved to 'output.json'

--- Remove by Keys ---
Enter comma-separated JSON keys to remove.
Press Enter to skip this step.
Keys to remove: metadata, _id

Removing keys: metadata, _id
✓ Results saved to 'output.json'

--- Continue or Exit ---
Are you satisfied with the results? (yes/no): yes

✓ Sanitization complete!
Final output saved to 'output.json'
```

## Sensitive Information Detection

The script automatically detects and removes:
- Email addresses
- Phone numbers
- Social Security Numbers (SSN)
- Credit card numbers
- IP addresses
- Keys containing sensitive keywords (password, secret, token, api_key, etc.)

When Presidio is available, it uses advanced ML-based detection. Otherwise, it falls back to regex patterns.

## Notes

- The output file is updated after each step, so you can check the results at any time
- Null values are automatically removed after each keyword/key removal step
- The script preserves the JSON structure while removing sensitive data
- Sensitive string values are replaced with placeholders like `[EMAIL_ADDRESS_REDACTED]`

