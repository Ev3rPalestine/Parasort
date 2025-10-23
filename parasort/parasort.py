#!/usr/bin/env python3
"""
PARASORT - URL Parameter Categorization & Extraction Tool for Penetration Testing

A tool that automatically categorizes URLs by their parameters and extracts them for efficient vulnerability testing. 
Organizes URLs by domain and vulnerability type to streamline security testing workflows.
"""

import argparse
import json
import sys
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from pathlib import Path
from collections import defaultdict
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init(autoreset=True)

class ParaSort:
    def __init__(self, config_file=None):
        # Set default config file location to ~/.parasort/parameter_categories.json
        if config_file is None:
            home_dir = os.path.expanduser("~")
            self.config_file = os.path.join(home_dir, ".parasort", "parameter_categories.json")
        else:
            self.config_file = config_file
            
        self.parameter_categories = self.load_config()
        
        self.category_colors = {
            'sqli': Fore.RED, 'xss': Fore.YELLOW, 'ssrf': Fore.CYAN, 'lfi': Fore.MAGENTA,
            'open_redirect': Fore.BLUE, 'command_injection': Fore.RED, 'auth_bypass': Fore.LIGHTRED_EX,
            'business_logic': Fore.LIGHTYELLOW_EX, 'info_disclosure': Fore.LIGHTCYAN_EX, 
            'custom': Fore.LIGHTMAGENTA_EX, 'custom-params': Fore.LIGHTMAGENTA_EX,
            'uncategorized': Fore.LIGHTBLACK_EX, 'error': Fore.RED
        }

    def load_config(self):
        """Load parameter categories from JSON config file"""
        default_config = {
            "sqli": [
                "id", "user_id", "product_id", "category_id", "page_id", "order_id", 
                "item_id", "post_id", "article_id", "news_id", "customer_id", "account_id",
                "uid", "uuid", "guid", "key", "code", "ref", "reference", "num", "number",
                "search", "query", "q", "s", "term", "keyword", "filter", "sort", "order",
                "username", "user", "email", "mail", "login", "password", "pass", "pwd",
                "name", "firstname", "lastname", "address", "phone", "mobile", "zip", "zipcode"
            ],
            "xss": [
                "q", "query", "search", "s", "keyword", "term", "find", "lookfor",
                "redirect", "return", "return_url", "return_to", "url", "link", "href",
                "message", "msg", "error", "err", "success", "info", "warning", "alert",
                "name", "title", "subject", "topic", "header", "footer", "description",
                "comment", "feedback", "review", "note", "content", "body", "text",
                "first_name", "last_name", "username", "email", "mail", "phone", "address",
                "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
                "gclid", "fbclid", "msclkid", "trk", "tracking", "campaign", "source"
            ],
            "ssrf": [
                "url", "link", "href", "image", "img", "picture", "pic", "photo", "avatar",
                "file", "path", "location", "redirect", "return", "return_url", "return_to",
                "callback", "cb", "next", "continue", "target", "destination", "goto",
                "load", "import", "include", "require", "fetch", "get", "post", "request",
                "endpoint", "api", "service", "proxy", "bridge", "gateway", "tunnel",
                "webhook", "hook", "notification", "alert", "ping", "health", "status"
            ],
            "lfi": [
                "file", "page", "path", "load", "include", "require", "import", "export",
                "document", "doc", "pdf", "docx", "template", "layout", "theme", "skin",
                "view", "display", "show", "content", "body", "text", "data", "info",
                "download", "upload", "attachment", "attach", "save", "open", "read",
                "config", "configuration", "setting", "profile", "preference", "option",
                "lang", "language", "locale", "country", "region", "currency", "timezone"
            ],
            "open_redirect": [
                "redirect", "redirect_uri", "redirect_url", "return", "return_url", "return_to",
                "next", "continue", "goto", "go", "target", "destination", "forward", "follow",
                "url", "link", "href", "location", "callback", "cb", "r", "u", "uri",
                "success", "success_url", "error", "error_url", "cancel", "cancel_url",
                "logout", "logout_url", "login", "login_url", "signin", "signin_url"
            ],
            "command_injection": [
                "cmd", "command", "exec", "execute", "run", "system", "process", "shell",
                "ping", "traceroute", "tracert", "nslookup", "dig", "whois", "host",
                "ip", "domain", "hostname", "server", "port", "service", "daemon",
                "script", "batch", "sh", "bash", "zsh", "python", "php", "perl", "ruby",
                "input", "output", "stdin", "stdout", "stderr", "pipe", "filter", "sort"
            ],
            "auth_bypass": [
                "admin", "administrator", "root", "superuser", "super", "moderator", "mod",
                "user", "username", "login", "email", "mail", "account", "member",
                "password", "pass", "pwd", "secret", "token", "key", "code", "pin",
                "session", "sessionid", "sessid", "sid", "cookie", "auth", "authentication",
                "access", "access_token", "refresh_token", "jwt", "bearer", "oauth",
                "privilege", "role", "permission", "right", "level", "status", "type"
            ],
            "business_logic": [
                "price", "cost", "amount", "total", "subtotal", "discount", "coupon", "promo",
                "quantity", "qty", "count", "number", "limit", "max", "min", "threshold",
                "status", "state", "phase", "stage", "step", "level", "tier", "grade",
                "role", "type", "category", "group", "class", "kind", "sort", "order",
                "user_id", "account_id", "customer_id", "order_id", "transaction_id",
                "balance", "credit", "debit", "points", "reward", "bonus", "commission"
            ],
            "info_disclosure": [
                "debug", "test", "testing", "demo", "development", "dev", "stage", "staging",
                "verbose", "verbose_mode", "trace", "tracing", "log", "logging", "logger",
                "error", "error_message", "err", "exception", "stack", "stacktrace", "traceback",
                "info", "information", "details", "full", "complete", "extended", "advanced",
                "config", "configuration", "setting", "env", "environment", "system", "server",
                "version", "v", "rev", "revision", "build", "release", "patch", "update"
            ]
        }
        
        try:
            # Create config directory if it doesn't exist
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
                
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                # Create default config file
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2)
                print(f"{Fore.YELLOW}Created default config: {self.config_file}")
                return default_config
        except Exception as e:
            print(f"{Fore.RED}Config error: {e}. Using defaults.")
            return default_config

    def normalize_parameter(self, param):
        """Normalize parameter name by URL decoding and handling special cases"""
        # URL decode the parameter
        decoded = unquote(param)
        
        # Handle encoded ampersands and other common encoding issues
        decoded = decoded.replace('amp;', '')  # Handle &amp; encoding
        
        # Remove common prefixes/suffixes that might vary
        normalized = decoded.lower().strip()
        
        return normalized

    def clear_parameters(self, url):
        """Clear parameter values, keeping only parameter names"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            cleared_params = {key: [''] for key in query_params.keys()}
            cleared_query = urlencode(cleared_params, doseq=True)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, cleared_query, parsed.fragment))
        except Exception:
            return url

    def categorize_url(self, url, categories_to_use, custom_params=None, clear_params=False):
        """Categorize a URL based on its parameters"""
        if clear_params:
            url = self.clear_parameters(url)
            
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        categories_found = set()
        matched_parameters = set()
        
        for param in query_params.keys():
            normalized_param = self.normalize_parameter(param)
            
            # Check custom parameters first
            if custom_params:
                for custom_param in custom_params:
                    if self.normalize_parameter(custom_param) == normalized_param:
                        categories_found.add('custom-params')
                        matched_parameters.add(param)
                        break
            
            # Check vulnerability categories
            for category in categories_to_use:
                if category in self.parameter_categories:
                    for category_param in self.parameter_categories[category]:
                        if self.normalize_parameter(category_param) == normalized_param:
                            categories_found.add(category)
                            matched_parameters.add(param)
                            break
                    
        return list(categories_found), url

    def extract_parameters_from_url(self, url):
        """Extract all parameter names from a URL"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            return set(query_params.keys())
        except Exception:
            return set()

    def process_urls(self, input_file, output_dir, categories_to_use, custom_params=None, 
                   clear_params=False, verbose=False, silent=False, extract_params=False,
                   urls_from_stdin=None):
        """Process all URLs from input file and/or stdin and categorize them by domain"""
        urls = []
        
        # Read URLs from stdin if provided
        if urls_from_stdin:
            urls.extend(urls_from_stdin)
        
        # Read URLs from file if provided
        if input_file and os.path.exists(input_file):
            try:
                with open(input_file, 'r', encoding='utf-8') as f:
                    file_urls = [line.strip() for line in f if line.strip()]
                    urls.extend(file_urls)
            except Exception as e:
                self.print_message(f"Error reading input file: {e}", Fore.RED, silent)
                return False
        elif input_file and not os.path.exists(input_file) and not urls_from_stdin:
            self.print_message(f"Error: Input file '{input_file}' not found", Fore.RED, silent)
            return False
        
        if not urls:
            self.print_message("Error: No URLs found in input", Fore.RED, silent)
            return False
            
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Statistics tracking
        domain_stats = defaultdict(lambda: defaultdict(int))
        category_parameters = defaultdict(lambda: defaultdict(set))
        domain_urls = defaultdict(list)
        domain_all_parameters = defaultdict(set)  # For parameter extraction
        all_parameters_global = set()  # For global parameter file
        total_urls = 0
        
        try:
            if not silent:
                mode_desc = "custom parameters" if custom_params else f"{len(categories_to_use)} categories"
                self.print_message(f"Processing {len(urls)} URLs using {mode_desc}...", Fore.CYAN, silent)
            
            # Group URLs by domain
            for url in urls:
                domain = self.get_domain_from_url(url)
                domain_urls[domain].append(url)
                
                # Extract parameters for parameter extraction feature
                if extract_params:
                    params = self.extract_parameters_from_url(url)
                    domain_all_parameters[domain].update(params)
                    all_parameters_global.update(params)
            
            # Process each domain
            for domain, domain_url_list in domain_urls.items():
                if not silent:
                    self.print_message(f"Processing: {Fore.GREEN}{domain}", Fore.WHITE, silent)
                
                domain_folder = output_path / domain
                domain_folder.mkdir(exist_ok=True)
                
                # Write parameters.txt for this domain if extract_params is enabled
                if extract_params and domain_all_parameters[domain]:
                    param_file = domain_folder / "parameters.txt"
                    with open(param_file, 'w', encoding='utf-8') as f:
                        for param in sorted(domain_all_parameters[domain]):
                            f.write(param + '\n')
                    if not silent:
                        self.print_message(f"  {Fore.GREEN}✓ Parameters saved: {param_file}", Fore.WHITE, silent)
                
                # Initialize category files (on-demand)
                category_files = {}
                
                # Process URLs for this domain
                for url in domain_url_list:
                    total_urls += 1
                    categories, processed_url = self.categorize_url(url, categories_to_use, custom_params, clear_params)
                    
                    if categories:
                        for category in categories:
                            # Create file if it doesn't exist
                            if category not in category_files:
                                filename = "custom-params-urls.txt" if category == "custom-params" else f"{category}-urls.txt"
                                file_path = domain_folder / filename
                                category_files[category] = open(file_path, 'w', encoding='utf-8')
                            
                            category_files[category].write(processed_url + '\n')
                            domain_stats[domain][category] += 1
                            
                            # Track parameters for this category
                            parsed = urlparse(processed_url)
                            query_params = parse_qs(parsed.query, keep_blank_values=True)
                            for param in query_params.keys():
                                category_parameters[domain][category].add(param)
                    else:
                        # Handle uncategorized URLs
                        if 'uncategorized' not in category_files:
                            category_files['uncategorized'] = open(domain_folder / "uncategorized-urls.txt", 'w', encoding='utf-8')
                        category_files['uncategorized'].write(processed_url + '\n')
                        domain_stats[domain]['uncategorized'] += 1
                
                # Close all files for this domain
                for file in category_files.values():
                    file.close()
            
            # Write all-parameters.txt if multiple domains and extract_params enabled
            if extract_params and len(domain_urls) > 1 and all_parameters_global:
                all_params_file = output_path / "all-parameters.txt"
                with open(all_params_file, 'w', encoding='utf-8') as f:
                    for param in sorted(all_parameters_global):
                        f.write(param + '\n')
                if not silent:
                    self.print_message(f"{Fore.GREEN}✓ All parameters saved: {all_params_file}", Fore.WHITE, silent)
            
            # Print detailed summary in verbose mode
            if verbose and not silent:
                self.print_detailed_summary(domain_stats, category_parameters)
            
            # Print final summary
            if not silent:
                self.print_summary(domain_stats, total_urls, output_dir, category_parameters)
            return True
            
        except Exception as e:
            self.print_message(f"Error: {str(e)}", Fore.RED, silent)
            return False

    def get_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            return domain if domain else "unknown_domain"
        except:
            return "unknown_domain"

    def print_message(self, message, color=Fore.WHITE, silent=False):
        if not silent:
            print(color + message)

    def print_detailed_summary(self, domain_stats, category_parameters):
        """Print detailed domain summary in verbose mode"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}DOMAIN SUMMARY")
        print(f"{Fore.CYAN}{'='*80}")
        
        for domain in sorted(domain_stats.keys()):
            if not domain_stats[domain]:
                continue
                
            print(f"\n{Fore.CYAN}📊 {domain}")
            print(f"{Fore.CYAN}{'-'*60}")
            
            for category, count in sorted(domain_stats[domain].items()):
                color = self.category_colors.get(category, Fore.WHITE)
                params = category_parameters[domain].get(category, set())
                
                print(f"  {color}{category:<18} : {count:>3} URLs", end="")
                if params:
                    print(f" {Fore.WHITE}| Parameters: {', '.join(sorted(params))}")
                else:
                    print()

    def print_summary(self, domain_stats, total_urls, output_dir, category_parameters):
        """Print final processing summary"""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"{Fore.CYAN}PROCESSING COMPLETE")
        print(f"{Fore.CYAN}{'='*50}")
        print(f"{Fore.WHITE}URLs processed: {Fore.YELLOW}{total_urls}")
        print(f"{Fore.WHITE}Domains found: {Fore.YELLOW}{len(domain_stats)}")
        
        # Calculate overall statistics
        overall_stats = defaultdict(int)
        all_category_params = defaultdict(set)
        
        for domain_stats_dict in domain_stats.values():
            for category, count in domain_stats_dict.items():
                overall_stats[category] += count
        
        for domain, categories in category_parameters.items():
            for category, params in categories.items():
                all_category_params[category].update(params)
        
        # Print category summary
        if overall_stats:
            print(f"\n{Fore.CYAN}📈 GLOBAL CATEGORY SUMMARY")
            print(f"{Fore.CYAN}{'-'*50}")
            
            for category, count in sorted(overall_stats.items(), key=lambda x: x[1], reverse=True):
                color = self.category_colors.get(category, Fore.WHITE)
                params = all_category_params.get(category, set())
                
                print(f"  {color}{category:<18} : {count:>5} URLs", end="")
                if params:
                    # Show first 5 parameters as examples
                    param_list = sorted(params)
                    display_params = param_list[:5]
                    param_text = f"{Fore.WHITE}| Parameters: {', '.join(display_params)}"
                    if len(param_list) > 5:
                        param_text += f" ... (+{len(param_list)-5} more)"
                    print(param_text)
                else:
                    print()
        else:
            print(f"{Fore.YELLOW}No categorized URLs found")
        
        print(f"{Fore.CYAN}{'='*50}")
        print(f"{Fore.GREEN}📁 Output directory: {Fore.YELLOW}{output_dir}/")
        print(f"{Fore.CYAN}{'='*50}")

    def show_categories(self, silent=False):
        """Show all available vulnerability categories"""
        if not silent:
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.CYAN}AVAILABLE VULNERABILITY CATEGORIES")
            print(f"{Fore.CYAN}{'='*60}")
            
            for category, params in self.parameter_categories.items():
                color = self.category_colors.get(category, Fore.WHITE)
                param_count = len(params)
                print(f"{color}{category:<20} {Fore.WHITE}({param_count} parameters)")
                # Show first 5 parameters as examples
                print(f"  {Fore.LIGHTBLACK_EX}{', '.join(params[:5])}...")
                
            print(f"{Fore.CYAN}{'='*60}")

def load_custom_params_from_file(file_path):
    """Load custom parameters from file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"{Fore.RED}Error loading parameters file: {e}")
        return None

def parse_comma_separated_params(param_string):
    """Parse comma-separated parameters into a list"""
    if not param_string:
        return []
    return [p.strip() for p in param_string.split(',') if p.strip()]

def print_logo(silent=False):
    """Print the PARASORT logo"""
    if silent:
        return
        
    logo = f"""
{Fore.CYAN}
██████╗  █████╗ ██████╗  █████╗ ███████╗ ██████╗ ██████╗ ████████╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝███████║██████╔╝███████║███████╗██║   ██║██████╔╝   ██║   
██╔═══╝ ██╔══██║██╔══██╗██╔══██║╚════██║██║   ██║██╔══██╗   ██║   
██║     ██║  ██║██║  ██║██║  ██║███████║╚██████╔╝██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
{Fore.YELLOW}                    URL Parameter Categorizer & Extraction
{Fore.LIGHTBLACK_EX}                         by Ev3rPalestine
    """
    print(logo)

def read_urls_from_stdin():
    """Read URLs from stdin if available"""
    if not sys.stdin.isatty():
        return [line.strip() for line in sys.stdin if line.strip()]
    return None

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.WHITE}PARASORT - URL Parameter Categorization & Extraction Tool for Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog=f"""
{Fore.CYAN}📋 {Fore.WHITE}EXAMPLES:{Style.RESET_ALL}
  {Fore.YELLOW}Basic usage:{Fore.WHITE}
    parasort -i urls.txt

  {Fore.YELLOW}Piped input from other tools:{Fore.WHITE}
    cat urls.txt | parasort

  {Fore.YELLOW}Specific vulnerabilities:{Fore.WHITE}  
    parasort -i urls.txt --vuln sqli xss

  {Fore.YELLOW}Custom parameters:{Fore.WHITE}
    parasort -i urls.txt -cp "id,user,cmd"
    parasort -i urls.txt -cpf my_params.txt

  {Fore.YELLOW}Extract parameters:{Fore.WHITE}
    parasort -i urls.txt -ep
    cat urls.txt | parasort -ep

{Fore.GREEN}👤 {Fore.WHITE}Author: {Fore.YELLOW}Ev3rPalestine{Style.RESET_ALL}
        """
    )
    
    # Help option
    
    parser.add_argument('-h', '--help', action='store_true',
                       help=f'{Fore.WHITE}Show this help message and exit{Style.RESET_ALL}')
    
    # Required arguments (only required if no stdin)
    required = parser.add_argument_group(f'{Fore.GREEN}🔧 REQUIRED ARGUMENTS{Style.RESET_ALL}')
    required.add_argument('-i', '--input', metavar='FILE',
                        help=f'{Fore.WHITE}Input file containing URLs (optional if using stdin){Style.RESET_ALL}')
    
    # Optional output argument with default
    processing = parser.add_argument_group(f'{Fore.BLUE}⚙️ PROCESSING OPTIONS{Style.RESET_ALL}')
    processing.add_argument('-o', '--output', default='results', metavar='DIR',
                          help=f'{Fore.WHITE}Output directory (default: results){Style.RESET_ALL}')
    processing.add_argument('--clear', action='store_true',
                          help=f'{Fore.WHITE}Clear parameter values, keep names only (e.g., --clear){Style.RESET_ALL}')
    processing.add_argument('-v', '--verbose', action='store_true',
                          help=f'{Fore.WHITE}Show detailed processing information (e.g., -v){Style.RESET_ALL}')
    processing.add_argument('-s', '--silent', action='store_true',
                          help=f'{Fore.WHITE}Minimal output for scripting (e.g., -s){Style.RESET_ALL}')
    processing.add_argument('--no-color', action='store_true',
                          help=f'{Fore.WHITE}Disable colored output (e.g., --no-color){Style.RESET_ALL}')
    
    # New parameter extraction option
    processing.add_argument('-ep', '--extract-params', action='store_true',
                          help=f'{Fore.WHITE}Extract all parameters to parameters.txt files (e.g., -ep){Style.RESET_ALL}')
    
    # Category selection
    categories = parser.add_argument_group(f'{Fore.MAGENTA}📊 VULNERABILITY CATEGORIES{Style.RESET_ALL}')
    categories.add_argument('--vuln', nargs='+', choices=['all', 'sqli', 'xss', 'ssrf', 'lfi', 
                         'open_redirect', 'command_injection', 'auth_bypass', 
                         'business_logic', 'info_disclosure'], default=['all'], metavar='CATEGORY',
                         help=f'{Fore.WHITE}Vulnerability categories (e.g., --vuln sqli xss){Style.RESET_ALL}')
    
    # Custom parameters
    custom = parser.add_argument_group(f'{Fore.YELLOW}🔍 CUSTOM PARAMETERS{Style.RESET_ALL}')
    custom_group = custom.add_mutually_exclusive_group()
    custom_group.add_argument('-cp', '--custom-params', nargs='+', metavar='PARAM',
                            help=f'{Fore.WHITE}Custom parameters (comma or space separated, e.g., -cp "id,user,cmd" or -cp id user cmd){Style.RESET_ALL}')
    custom_group.add_argument('-cpf', '--custom-params-file', metavar='FILE',
                            help=f'{Fore.WHITE}File with custom parameters (e.g., -cpf params.txt){Style.RESET_ALL}')
    
    # Information
    info = parser.add_argument_group(f'{Fore.CYAN}ℹ️ INFORMATION{Style.RESET_ALL}')
    info.add_argument('-sc', '--show-categories', action='store_true',
                     help=f'{Fore.WHITE}List available vulnerability categories{Style.RESET_ALL}')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Show help if requested or no arguments provided
    if args.help or len(sys.argv) == 1:
        print_logo()
        parser.print_help()
        return
    
    # Disable colors if requested
    if args.no_color:
        for color in Fore.__dict__.keys():
            setattr(Fore, color, '')
    
    # Print logo unless silent mode
    print_logo(args.silent)
    
    # Handle information commands first - these shouldn't require input files
    if args.show_categories:
        parasort = ParaSort()
        parasort.show_categories(args.silent)
        return
    
    # Check if we have input from stdin or file
    urls_from_stdin = read_urls_from_stdin()
    
    if not args.input and not urls_from_stdin:
        print(f"{Fore.RED}Error: No input provided. Use -i/--input or pipe URLs to stdin.")
        print(f"{Fore.YELLOW}Use parasort --help for usage information")
        sys.exit(1)
    
    parasort = ParaSort()
    
    # Determine categories to use
    categories_to_use = list(parasort.parameter_categories.keys()) if 'all' in args.vuln else args.vuln
    
    # Handle custom parameters
    custom_params = None
    if args.custom_params:
        # Handle both comma-separated and space-separated parameters
        if len(args.custom_params) == 1 and ',' in args.custom_params[0]:
            # Comma-separated string
            custom_params = parse_comma_separated_params(args.custom_params[0])
        else:
            # Space-separated parameters
            custom_params = args.custom_params
        
        if not args.silent:
            print(f"{Fore.GREEN}Custom parameters: {', '.join(custom_params[:10])}..." if len(custom_params) > 10 else f"{Fore.GREEN}Custom parameters: {', '.join(custom_params)}")
    elif args.custom_params_file:
        custom_params = load_custom_params_from_file(args.custom_params_file)
        if custom_params is None:
            sys.exit(1)
        if not args.silent:
            print(f"{Fore.GREEN}Loaded {len(custom_params)} parameters from {args.custom_params_file}")
    
    # Process URLs
    success = parasort.process_urls(
        input_file=args.input,
        output_dir=args.output,
        categories_to_use=categories_to_use,
        custom_params=custom_params,
        clear_params=args.clear,
        verbose=args.verbose,
        silent=args.silent,
        extract_params=args.extract_params,
        urls_from_stdin=urls_from_stdin
    )
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()