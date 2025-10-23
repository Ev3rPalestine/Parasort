# Parasort - URL Parameter Categorization & Extraction Tool

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
URL Parameter Categorizer & Extraction
by Ev3rPalestine
```

#### A powerful Python tool for automatically categorizing URLs by their parameters & extracting them to streamline penetration testing and vulnerability assessment workflows.

## Features

- **Automatic URL Categorization**: Sort URLs by vulnerability type (SQLi, XSS, SSRF, LFI, etc.)
- **Domain-Based Organization**: Output organized by domain folders
- **Paramters Extraction**: Extract found parameters in urls for fuzzing or other use
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

git clone https://github.com/Ev3rPalestine/Parasort.git
cd Parasort
pip3 install .
```
## Example

```bash
# parasort -i urls.txt


██████╗  █████╗ ██████╗  █████╗ ███████╗ ██████╗ ██████╗ ████████╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝███████║██████╔╝███████║███████╗██║   ██║██████╔╝   ██║   
██╔═══╝ ██╔══██║██╔══██╗██╔══██║╚════██║██║   ██║██╔══██╗   ██║   
██║     ██║  ██║██║  ██║██║  ██║███████║╚██████╔╝██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                    URL Parameter Categorizer & Extraction
                         by Ev3rPalestine
    
Processing 858 URLs using 9 categories...
Processing: example.com
Processing: example.org
Processing: example2.com

==================================================
PROCESSING COMPLETE
==================================================
URLs processed: 858
Domains found: 22

📈 GLOBAL CATEGORY SUMMARY
--------------------------------------------------
  uncategorized      :   641 URLs
  xss                :   122 URLs| Parameters: AdvertiserID, _charset_, _gl, belboon, dclid ... (+33 more)
  info_disclosure    :    66 URLs| Parameters: v
  sqli               :    21 URLs| Parameters: _charset_, cnt, groupId, id, k ... (+13 more)
  business_logic     :     8 URLs| Parameters: actionId, advancePaymentId, backLink, calcType, carModel ... (+25 more)
  ssrf               :     7 URLs| Parameters: id, image, k, limit, offset ... (+5 more)
  lfi                :     6 URLs| Parameters: ANAME, FNAME, LAF_PARTNER, Page, action ... (+9 more)
  open_redirect      :     6 URLs| Parameters: id, k, limit, offset, p_l_id ... (+4 more)
==================================================
📁 Output directory: results/

```

## Available Arguments
```text
Options:

ℹ️ INFORMATION:
  -h, --help            Show this help message and exit
  -sc, --show-categories     List available vulnerability categories

🔧 REQUIRED ARGUMENTS:
  -i, --input FILE      Input file containing URLs (e.g., -i urls.txt)
  -o, --output DIR      Output directory (e.g., -o results)

⚙️ PROCESSING OPTIONS:
  --clear               Clear parameter values, keep names only (e.g., --clear)
  -v, --verbose         Show detailed processing information (e.g., -v)
  -s, --silent          Minimal output for scripting (e.g., -s)
  --no-color            Disable colored output (e.g., --no-color)
  -ep, --extract-params Extract all parameters to parameters.txt files

📊 VULNERABILITY CATEGORIES:
  --vuln CATEGORY [CATEGORY ...]
                        Vulnerability categories (e.g., --vuln sqli xss)

🔍 CUSTOM PARAMETERS:
  -cp, --custom-params PARAM [PARAM ...]
                        Custom parameters (comma or space separated, e.g., -cp "id,user,cmd" or -cp id user
                        cmd)
  -cpf, --custom-params-file FILE
                        File with custom parameters (e.g., -cpf params.txt)

📋 EXAMPLES:
  Basic usage:
    parasort -i urls.txt -o results
    cat urls.txt | parasort -o results

  Specific vulnerabilities:  
    parasort -i urls.txt -o results --vuln sqli xss

  Custom parameters:
    parasort -i urls.txt -o results -cp "id,user,cmd"
    parasort -i urls.txt -o results -cpf my_params.txt

  Advanced options:
    parasort -i urls.txt -o results --clear -v
```

## Basic Usage

```bash
# Show help with all examples
parasort -h

# Show categories
parasort -sc

# Process custom parameters and clearing their values
parasort -i urls.txt -o results -cp "id,token,api_key,session" --clear

# Process with specific vulnerabilities only
parasort -i urls.txt -o results --vuln sqli xss -v

# Silent mode
parasort -i urls.txt -o results -s
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

    -cp, --custom-params PARAM - Custom parameters to search for (comma or space separated)

    -cpf, --custom-params-file FILE - File with custom parameters (one per line)

#### - Information

    -h, --help - Show help message and exit
    -sc, --show-categories - List available vulnerability categories


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
│   ├── parameters.txt          
│   └── uncategorized-urls.txt
├── target.org/
│   ├── sqli-urls.txt
│   ├── xss-urls.txt
│   ├── parameters.txt          
│   └── ...
└── all-parameters.txt   
```

## Configuration
#### - Parameter Categories File

The parameter_categories.json file is created and located in directory named ".parasort" in the home directory of the user, it defines which parameters belong to each vulnerability category. You can customize this file to add or remove parameters:

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

