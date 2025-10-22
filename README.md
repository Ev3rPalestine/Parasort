# Parasort - URL Parameter Categorization Tool

![PARASORT Logo](https://img.shields.io/badge/PARASORT-URL%20Parameter%20Categorizer-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Author](https://img.shields.io/badge/Author-Ev3rPalestine-orange)

```bash
██████╗  █████╗ ██████╗  █████╗ ███████╗ ██████╗ ██████╗ ████████╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝███████║██████╔╝███████║███████╗██║   ██║██████╔╝   ██║
██╔═══╝ ██╔══██║██╔══██╗██╔══██║╚════██║██║   ██║██╔══██╗   ██║
██║     ██║  ██║██║  ██║██║  ██║███████║╚██████╔╝██║  ██║   ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
URL Parameter Categorizer
by Ev3rPalestine
```

#### A powerful Python tool for automatically categorizing URLs by their parameters to streamline penetration testing and vulnerability assessment workflows.

## Features

- **Automatic URL Categorization**: Sort URLs by vulnerability type (SQLi, XSS, SSRF, LFI, etc.)
- **Domain-Based Organization**: Output organized by domain folders
- **Custom Parameter Search**: Support for custom parameters via command line or file
- **Parameter Value Clearing**: Clean URLs by keeping only parameter names
- **Flexible Category Selection**: Choose specific vulnerability types or process all
- **Configurable Parameters**: External JSON configuration for easy updates
- **Colorful Output**: Visual feedback with color-coded categories

## Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Quick Setup

```bash
# Clone the repository

git clone https://github.com/Ev3rPalestine/parasort.git
cd parasort

# Install dependencies
pip install -r requirements.txt
```
## Help
```bash
Options:
  -h, --help            Show this help message and exit

🔧 REQUIRED ARGUMENTS:
  -i, --input FILE      Input file containing URLs (e.g., -i urls.txt)
  -o, --output DIR      Output directory (e.g., -o results)

⚙️ PROCESSING OPTIONS:
  --clear               Clear parameter values, keep names only (e.g., --clear)
  -v, --verbose         Show detailed processing information (e.g., -v)
  -s, --silent          Minimal output for scripting (e.g., -s)
  --no-color            Disable colored output (e.g., --no-color)

📊 VULNERABILITY CATEGORIES:
  --vuln CATEGORY [CATEGORY ...]
                        Vulnerability categories (e.g., --vuln sqli xss)

🔍 CUSTOM PARAMETERS:
  -cp, --custom-params PARAM [PARAM ...]
                        Custom parameters (comma or space separated, e.g., -cp "id,user,cmd" or -cp id user
                        cmd)
  -f, --custom-params-file FILE
                        File with custom parameters (e.g., -f params.txt)

ℹ️ INFORMATION:
  --show-categories     List available vulnerability categories (e.g., --show-categories)

📋 EXAMPLES:
  Basic usage:
    parasort.py -i urls.txt -o results

  Specific vulnerabilities:  
    parasort.py -i urls.txt -o output --vuln sqli xss

  Custom parameters:
    parasort.py -i urls.txt -o output -cp "id,user,cmd"
    parasort.py -i urls.txt -o output -f my_params.txt

  Advanced options:
    parasort.py -i urls.txt -o output --clear -v
```

## Basic Usage

```bash
# Show help with all examples
python parasort.py -h

# Show categories
python parasort.py --show-categories

# Process with comma-separated custom parameters
python parasort.py -i urls.txt -o results -cp "id,token,api_key,session" --clear

# Process with specific vulnerabilities only
python parasort.py -i urls.txt -o output --vuln sqli xss -v

# Silent mode for scripting
python parasort.py -i urls.txt -o output -s
```

## Command Line Options
#### - Required Arguments

    -i, --input FILE - Input file containing URLs (required)

    -o, --output DIR - Output directory (default: results)

#### - Processing Options

    --clear - Clear parameter values, keep names only

    -v, --verbose - Show detailed processing information

    -s, --silent - Minimal output (for scripting)

    --no-color - Disable colored output

#### - Vulnerability Categories

    --vuln CATEGORY - Vulnerability categories (default: all)

        Available: all, sqli, xss, ssrf, lfi, open_redirect, command_injection, auth_bypass, business_logic, info_disclosure

#### - Custom Parameters

    -c, --custom-params PARAM - Custom parameters to search for

    -f, --custom-params-file FILE - File with custom parameters (one per line)

#### - Information

    --show-categories - List available vulnerability categories


## Output Structure

The tool creates domain-based folders with categorized URL files:
text

```bash
results/
├── example.com/
│   ├── sqli-urls.txt
│   ├── xss-urls.txt
│   ├── ssrf-urls.txt
│   ├── custom-urls.txt
│   └── uncategorized-urls.txt
├── target.org/
│   ├── sqli-urls.txt
│   ├── xss-urls.txt
│   └── ...
└── ...
```

## Configuration
#### - Parameter Categories File

The parameter_categories.json file defines which parameters belong to each vulnerability category. You can customize this file to add or remove parameters:

```json
{
  "sqli": ["id", "user_id", "product_id"],
  "xss": ["q", "search", "query"],
  "ssrf": ["url", "redirect", "image"],
  ...
}
```

* The file is automatically created on first run if it doesn't exist.


#### - Adding New Vulnerability Categories
* Edit parameter_categories.json
* Add your new category with relevant parameters
* The tool will automatically detect the new category

#### - Using Custom Parameter Files

Create a text file with one parameter per line:

```text
api_key
session_token
user_id
admin
debug
```

### - License

```text
This project is licensed under the MIT License - see the LICENSE file for details.
Author

Note: This tool is intended for legitimate security testing and educational purposes only. Always ensure you have proper authorization before testing any systems.
```

