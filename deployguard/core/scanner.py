"""Secret scanner engine for detecting exposed secrets in code."""

import hashlib
import math
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml
from detect_secrets import SecretsCollection
from detect_secrets.core import scan
from detect_secrets.settings import default_settings

from deployguard.core.exceptions import ScanError
from deployguard.core.models import Finding, SecretType, Severity


class SecretPattern:
    """Represents a secret detection pattern."""

    def __init__(
        self,
        name: str,
        pattern: str,
        secret_type: str,
        severity: str,
        description: str = "",
        remediation: str = "",
    ):
        """Initialize a secret pattern."""
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        # Accept any string as secret_type for flexibility with 800+ patterns
        try:
            self.secret_type = SecretType(secret_type)
        except ValueError:
            # Create a dynamic type if not in enum (for new patterns)
            self.secret_type = secret_type  # Store as string
        self.severity = Severity(severity)
        self.description = description
        self.remediation = remediation


# Pre-compiled regex patterns for value extraction (CRITICAL for performance!)
# These are compiled ONCE at module load, not on every method call
_RE_JSON_KV = re.compile(r'"([^"]+)"\s*:\s*"([^"]+)"', re.IGNORECASE)
_RE_JSON_SINGLE = re.compile(r"'([^']+)'\s*:\s*'([^']+)'", re.IGNORECASE)
_RE_JSON_MIXED = re.compile(r'''["']([^"']+)["']\s*:\s*["']([^"']+)["']''', re.IGNORECASE)
_RE_BROKEN_JSON = re.compile(r'(\w+)"\s*:\s*"([^"]+)"', re.IGNORECASE)
_RE_CONN_STRING = re.compile(r'Password\s*=\s*([^;"\'\s]+)', re.IGNORECASE)
_RE_ASSIGNMENT = re.compile(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["\']?(.+?)["\']?$', re.IGNORECASE)
_RE_VAR_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,20}$')


class SecretScanner:
    """
    Scans code for exposed secrets using pattern matching and entropy analysis.

    This class implements the core secret detection engine with support for:
    - Regex pattern matching
    - Entropy-based detection
    - File filtering
    - Context extraction
    """

    def __init__(self, patterns_file: Optional[str] = None, max_file_size: int = 500_000):
        """
        Initialize the secret scanner.

        Args:
            patterns_file: Path to YAML file with secret patterns
            max_file_size: Maximum file size in bytes to scan (default: 500KB)
        """
        self.patterns: List[SecretPattern] = []
        self.file_includes: List[str] = []
        self.file_excludes: List[str] = []
        self.entropy_enabled: bool = True
        self.min_entropy: float = 5.0  # Increased from 4.5 to reduce false positives
        self.min_length: int = 16  # Increased from 20 - real secrets are at least 16 chars
        self.max_file_size: int = max_file_size
        
        # Exclusion patterns for false positive filtering
        self.exclusion_patterns: Dict[str, List[re.Pattern]] = {}
        self.false_positive_patterns: List[re.Pattern] = []
        self.public_tokens: Set[str] = set()
        self.path_exclusion_patterns: List[re.Pattern] = []
        
        # Default binary/archive extensions to always skip
        self.skip_extensions: Set[str] = {
            '.tgz', '.tar', '.gz', '.zip', '.rar', '.7z',
            '.exe', '.dll', '.so', '.dylib', '.bin',
            '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.mp3', '.mp4', '.wav', '.avi', '.mov', '.wmv',
            '.ttf', '.otf', '.woff', '.woff2', '.eot',
            '.pyc', '.pyo', '.class', '.o', '.obj',
            '.sqlite', '.db', '.sqlite3',
            '.pack', '.idx',  # Git pack files
            '.min.js', '.min.css',  # Minified files
        }

        # Load patterns from config
        if patterns_file:
            self._load_patterns(patterns_file)
        else:
            # Load default patterns
            default_path = Path(__file__).parent.parent / "config" / "secret_patterns.yaml"
            if default_path.exists():
                self._load_patterns(str(default_path))

    def _load_patterns(self, patterns_file: str) -> None:
        """Load secret patterns from YAML file."""
        try:
            with open(patterns_file, "r") as f:
                config = yaml.safe_load(f)

            # Load detection patterns
            for pattern_def in config.get("patterns", []):
                self.patterns.append(
                    SecretPattern(
                        name=pattern_def["name"],
                        pattern=pattern_def["pattern"],
                        secret_type=pattern_def["secret_type"],
                        severity=pattern_def["severity"],
                        description=pattern_def.get("description", ""),
                        remediation=pattern_def.get("remediation", ""),
                    )
                )

            # Load file patterns
            file_patterns = config.get("file_patterns", {})
            self.file_includes = file_patterns.get("include", [])
            self.file_excludes = file_patterns.get("exclude", [])

            # Load entropy settings
            entropy_config = config.get("entropy", {})
            self.entropy_enabled = entropy_config.get("enabled", True)
            self.min_entropy = entropy_config.get("min_entropy", 4.5)
            self.min_length = entropy_config.get("min_length", 20)
            
            # Load global allowlists and exclusions
            global_allowlists = config.get("global_allowlists", {})
            
            # Load path exclusions from global_allowlists
            path_exclusions = global_allowlists.get("paths", [])
            self.path_exclusion_patterns: List[re.Pattern] = []
            for path_pattern in path_exclusions:
                try:
                    self.path_exclusion_patterns.append(re.compile(path_pattern))
                except re.error:
                    pass
            
            # Load false positive patterns
            for fp_pattern in global_allowlists.get("false_positive_patterns", []):
                try:
                    self.false_positive_patterns.append(re.compile(fp_pattern, re.IGNORECASE))
                except re.error:
                    pass
            
            # Load exclusion patterns by category
            exclusions = global_allowlists.get("exclusions", {})
            for category, patterns in exclusions.items():
                if category == "public_tokens":
                    # Store public tokens as a set for fast lookup
                    self.public_tokens = set(patterns)
                else:
                    # Compile regex patterns
                    compiled = []
                    for pattern in patterns:
                        try:
                            compiled.append(re.compile(pattern, re.IGNORECASE))
                        except re.error:
                            pass
                    if compiled:
                        self.exclusion_patterns[category] = compiled

        except Exception as e:
            raise ScanError(f"Failed to load patterns file: {e}")

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Scan a single file for secrets.

        Args:
            file_path: Path to the file being scanned
            content: File content as string

        Returns:
            List of Finding objects
        """
        findings: List[Finding] = []

        # Skip if file should be excluded
        if self._should_exclude_file(file_path):
            return findings

        # Split content into lines for line-by-line analysis
        lines = content.split("\n")

        # Pattern-based detection
        for pattern in self.patterns:
            matches = pattern.pattern.finditer(content)
            for match in matches:
                line_number = content[: match.start()].count("\n") + 1
                column_start = match.start() - content.rfind("\n", 0, match.start())

                # Extract variable name and value from the match
                variable_name, actual_value = self._extract_variable_and_value(
                    match.group(0), match.groups()
                )
                
                # Get the full line for context-based exclusion
                current_line = lines[line_number - 1] if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive(match.group(0), actual_value, current_line, file_path):
                    continue

                # CRITICAL: Use actual_value for exposed_value when available!
                # This ensures git history cleanup only replaces the SECRET VALUE,
                # not the entire JSON key-value structure (which would break code)
                secret_value_for_cleanup = actual_value if actual_value else match.group(0)
                
                finding = Finding(
                    type=pattern.secret_type,
                    severity=pattern.severity,
                    file_path=file_path,
                    line_number=line_number,
                    column_start=column_start,
                    column_end=column_start + len(match.group(0)),
                    exposed_value=secret_value_for_cleanup,  # Only the secret value!
                    exposed_value_hash=self._hash_value(secret_value_for_cleanup),
                    suggested_variable=variable_name or self._suggest_env_var(pattern.secret_type, file_path),
                    description=pattern.description,
                    remediation=pattern.remediation,
                    context=self._extract_context(lines, line_number),
                    metadata={
                        "variable_name": variable_name,
                        "actual_value": actual_value,
                        "full_match": match.group(0),  # Keep full match for reference
                        "pattern_name": pattern.name,
                    }
                )
                findings.append(finding)

        # Entropy-based detection
        if self.entropy_enabled:
            entropy_findings = self._detect_high_entropy(file_path, content)
            findings.extend(entropy_findings)

        return findings

    def _extract_variable_and_value(
        self, full_match: str, groups: Tuple
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract variable name and value from a pattern match.
        
        CRITICAL: Uses pre-compiled regex patterns (module-level constants) for performance.
        This method is called thousands of times during a scan - regex compilation
        must happen ONCE at module load, not on every call.
        
        Args:
            full_match: The full matched string
            groups: Captured groups from the regex
            
        Returns:
            Tuple of (variable_name, actual_value)
        """
        # Pattern 1: Standard JSON - "key": "value"
        json_match = _RE_JSON_KV.search(full_match)
        if json_match:
            return json_match.group(1).upper().replace(' ', '_').replace('-', '_'), json_match.group(2)
        
        # Pattern 2: Single quotes JSON - 'key': 'value'
        json_single_match = _RE_JSON_SINGLE.search(full_match)
        if json_single_match:
            return json_single_match.group(1).upper().replace(' ', '_').replace('-', '_'), json_single_match.group(2)
        
        # Pattern 3: Mixed quotes
        json_mixed_match = _RE_JSON_MIXED.search(full_match)
        if json_mixed_match:
            return json_mixed_match.group(1).upper().replace(' ', '_').replace('-', '_'), json_mixed_match.group(2)
        
        # Pattern 4: Broken JSON pattern like: Key": "value"
        broken_match = _RE_BROKEN_JSON.search(full_match)
        if broken_match:
            return broken_match.group(1).upper(), broken_match.group(2)
        
        # Connection strings - keep whole string
        conn_match = _RE_CONN_STRING.search(full_match)
        if conn_match:
            return "CONNECTION_STRING", full_match
        
        # Assignment patterns: VAR=value
        match = _RE_ASSIGNMENT.match(full_match.strip())
        if match:
            return match.group(1).upper(), match.group(2)
        
        # Fallback - use captured groups
        variable_name = None
        actual_value = None
        
        if groups:
            potential_values = []
            potential_vars = []
            
            for group in groups:
                if group:
                    group_str = str(group)
                    if _RE_VAR_NAME.match(group_str) and len(group_str) < 30:
                        potential_vars.append(group_str)
                    else:
                        potential_values.append(group_str)
            
            if potential_vars:
                variable_name = potential_vars[0].upper()
            if potential_values:
                actual_value = max(potential_values, key=len)
        
        if not actual_value:
            actual_value = full_match.strip().strip('"\'')
        
        return variable_name, actual_value
    
    def _is_false_positive(self, matched_value: str, actual_value: Optional[str], line: str, file_path: str) -> bool:
        """
        Check if a matched value is a false positive.
        
        Args:
            matched_value: The full matched string
            actual_value: The extracted actual secret value
            line: The full line containing the match
            file_path: Path to the file being scanned
            
        Returns:
            True if this is a false positive, False otherwise
        """
        value_to_check = actual_value or matched_value
        file_lower = file_path.lower() if file_path else ""
        
        # =================================================================
        # FILE-BASED EXCLUSIONS - Skip entire file types known for FPs
        # =================================================================
        # These file types are notorious for false positives
        skip_file_patterns = [
            r'\.min\.js$',         # Minified JavaScript
            r'\.min\.css$',        # Minified CSS
            r'\.bundle\.js$',      # Bundled JavaScript
            r'\.chunk\.js$',       # Webpack chunks
            r'\.map$',             # Source maps
            r'/vendor/',           # Vendor directories
            r'/node_modules/',     # Node modules
            r'/dist/',             # Distribution folders
            r'/build/',            # Build folders
            r'\.css$',             # CSS files often have base64 fonts
            r'package-lock\.json$', # npm lock files
            r'yarn\.lock$',        # Yarn lock files
            r'composer\.lock$',    # PHP composer lock
            r'\.suo$',             # Visual Studio user options (binary)
            r'\.user$',            # User settings files
            r'\.DotSettings\.user$', # ReSharper/Rider user settings
            r'\.DotSettings$',     # ReSharper/Rider settings
            r'karma\.conf\.js$',   # Karma test config
            r'\.csproj$',          # C# project files (build configs, not secrets)
            r'\.vbproj$',          # VB project files
            r'\.fsproj$',          # F# project files
            r'\.scss$',            # SASS files
            r'\.less$',            # LESS files
        ]
        for skip_pattern in skip_file_patterns:
            if re.search(skip_pattern, file_lower, re.IGNORECASE):
                return True
        
        # =================================================================
        # HTML/ANGULAR TEMPLATE DETECTION - These are NOT secrets!
        # =================================================================
        html_file = file_lower.endswith('.html') or file_lower.endswith('.component.html') or file_lower.endswith('.ejs')
        ts_file = file_lower.endswith('.ts') or file_lower.endswith('.component.ts')
        
        # Skip Angular/HTML templates entirely for entropy detection
        if html_file:
            # Only keep actual credential patterns in HTML (very rare)
            # Skip HTML content, Angular bindings, etc.
            html_fp_patterns = [
                r'^\s*>',                       # Starts with > (HTML tag content)
                r'<\w+',                        # HTML tags
                r'\{\{[\w.]+\}\}',              # Angular interpolation {{var}}
                r'\*ngIf',                      # Angular structural directives
                r'\*ngFor',                     # Angular structural directives
                r'\[[\w.]+\]',                  # Angular property binding [prop]
                r'\([\w.]+\)',                  # Angular event binding (click)
                r'class\s*=',                   # HTML class attribute
                r'style\s*=',                   # HTML style attribute
                r'<mat-',                       # Angular Material components
                r'<span|<div|<p>|<a\s',         # Common HTML tags
                r'&gt;|&lt;|&amp;',             # HTML entities
                r'<strong>|<del>|<em>',         # HTML formatting tags
                # HTML meta tag patterns (viewport settings are NOT secrets!)
                r'width=device-width',          # viewport meta tag
                r'initial-scale=',              # viewport meta tag
                r'viewport-fit=',               # viewport meta tag
                r'<meta\s+',                    # meta tags
                r'name=["\']viewport["\']',     # viewport meta tag
                r'content=["\'].*["\']',        # meta tag content
            ]
            for pattern in html_fp_patterns:
                if re.search(pattern, value_to_check, re.IGNORECASE):
                    return True
        
        # =================================================================
        # GITHUB ACTIONS / CI/CD YAML - These are NOT secrets!
        # =================================================================
        is_workflow_file = '.github/workflows/' in file_path or file_lower.endswith(('.yml', '.yaml'))
        if is_workflow_file or 'github' in value_to_check.lower():
            github_actions_patterns = [
                r'\$\{\{\s*.*\s*\}\}',          # ${{ github.sha }}
                r'steps\.',                      # steps.deploy.outputs.url
                r'github\.',                     # github.repository
                r'runner\.os',                   # runner.os
                r'secrets\.\w+',                 # secrets.GITHUB_TOKEN (reference, not value)
                r'echo\s+["\']',                 # echo "message"
                r'run:\s*\|',                    # YAML multiline
                r'uses:\s*actions/',             # uses: actions/checkout@v2
                r'with:\s*$',                    # YAML with: block
                r'env:\s*$',                     # YAML env: block
            ]
            for pattern in github_actions_patterns:
                if re.search(pattern, value_to_check, re.IGNORECASE):
                    return True
        
        # =================================================================
        # C# CODE PATTERNS - These are NOT secrets!
        # =================================================================
        csharp_fp_patterns = [
            r'\.Sum\s*\(\s*\w+\s*=>\s*\w+\.\w+\)',  # LINQ .Sum(p => p.x)
            r'Convert\.To\w+\(',               # Convert.ToInt32(
            r'\.Split\s*\(',                   # string.Split(
            r'\{\w+\}\s*\{\w+\}',              # String interpolation {x} {y}
            r'^\s*\w+\s*=\s*"[^"]*";\s*$',     # Simple string assignment
            r'urn:\w+:',                       # URN identifiers (claim types)
            r'@EntryIndexedValue',             # ReSharper settings
            r'/Default/CodeStyle/',            # ReSharper settings paths
            r'AutoDetectedNamingRules',        # ReSharper naming rules
        ]
        for pattern in csharp_fp_patterns:
            if re.search(pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # URL WITHOUT CREDENTIALS - These are NOT secrets!
        # =================================================================
        # URLs to documentation, public sites without embedded passwords
        public_url_patterns = [
            r'^https?://(www\.)?nodejs\.org',
            r'^https?://(www\.)?material\.io',
            r'^https?://(www\.)?karma-runner\.github\.io',
            r'^https?://(www\.)?github\.com',
            r'^https?://(www\.)?npmjs\.com',
            r'^https?://(www\.)?docs\.',
            r'^https?://[a-z0-9.-]+\s*(,|$)',  # URL followed by comma or end (no creds)
        ]
        for pattern in public_url_patterns:
            if re.search(pattern, value_to_check, re.IGNORECASE):
                # Make sure there's no password= or key= in it
                if not re.search(r'(password|pwd|secret|key|token|auth)=\w{6,}', value_to_check, re.IGNORECASE):
                    return True
        
        # =================================================================
        # LOG/DEBUG MESSAGES - These are NOT secrets!
        # =================================================================
        log_patterns = [
            r'GetFlights with \{',             # Logging template
            r'@response\}',                    # Serilog template
            r'response:\s*\{@',                # Serilog structured logging
            r'\./mobileHub/',                  # API endpoint examples in comments
        ]
        for pattern in log_patterns:
            if re.search(pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # ALPHABET/TEST STRINGS - These are NOT secrets!
        # =================================================================
        if value_to_check == "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
            return True
        if re.match(r'^[A-Z]{26}[0-9]+$', value_to_check):  # Full alphabet + numbers
            return True
        
        # =================================================================
        # BINARY/CORRUPTED DATA - These are NOT secrets!
        # =================================================================
        # Binary files have lots of unprintable characters
        unprintable_count = sum(1 for c in value_to_check if ord(c) < 32 or ord(c) > 126)
        if unprintable_count > len(value_to_check) * 0.3:  # >30% unprintable
            return True
        
        # =================================================================
        # MINIFIED JAVASCRIPT DETECTION - These are NOT secrets!
        # =================================================================
        # Minified JS has distinctive patterns - long lines with dense code
        minified_js_indicators = [
            r'\}var\s+\w+=',                    # }var x=
            r',\w+=this\.',                     # ,l=this.
            r'\.prototype\.\w+=function',       # .prototype.x=function
            r'return\s*!\d+===',                # return!1===
            r'\w+\.\w+\.\w+\.\w+\(',            # a.b.c.d(
            r'function\s*\(\w\)\{',             # function(e){
            r'\}\)\(\w+\)',                     # })(e)
            r':\{\},\w+:\{\}',                  # :{},b:{}
            r'\w+\|\|\(\w+=\{\}\)',             # a||(a={})
            r',\w+\.\w+=\w+\.\w+,',             # ,a.b=c.d,
            r'\w+\["\w+"\]=',                   # a["b"]=
            r'\.call\(this,\w+\)',              # .call(this,e)
            r'\.apply\(this,arguments\)',       # .apply(this,arguments)
            r'\?\w+\(\w+\):void\s+0',           # ?f(e):void 0
        ]
        for minified_pattern in minified_js_indicators:
            if re.search(minified_pattern, value_to_check):
                return True
        
        # =================================================================
        # JAVASCRIPT CODE DETECTION - These are NOT secrets!
        # =================================================================
        js_code_indicators = [
            r'^var\s+\w+=',                     # var x=
            r'^let\s+\w+=',                     # let x=
            r'^const\s+\w+=',                   # const x=
            r'^function\s*\w*\s*\(',            # function name(
            r'^return\s+(this|true|false|null)', # return this/true/false/null
            r'\.innerHTML\}?',                  # .innerHTML
            r'\.offsetHeight',                  # .offsetHeight
            r'\.appendChild\(',                 # .appendChild(
            r'\.getElementById\(',              # .getElementById(
            r'\.querySelector\(',               # .querySelector(
            r'\.addEventListener\(',            # .addEventListener(
            r'\.createElement\(',               # .createElement(
            r'\.setAttribute\(',                # .setAttribute(
            r'\.classList\.',                   # .classList.add/remove
            r'\.style\.\w+\s*=',                # .style.color =
            r'document\.\w+',                   # document.something
            r'window\.\w+',                     # window.something
            r'this\.\w+\s*=',                   # this.x =
            r'new\s+Array\(',                   # new Array(
            r'new\s+Object\(',                  # new Object(
            r'JSON\.(parse|stringify)\(',       # JSON.parse/stringify
            r'Array\.prototype\.',              # Array.prototype.
            r'Object\.(keys|values|entries)\(', # Object.keys/values/entries
            r'Math\.(floor|ceil|round|random)', # Math functions
            r'parseInt\(|parseFloat\(',         # parseInt/parseFloat
            r'typeof\s+\w+',                    # typeof something
            r'instanceof\s+\w+',                # instanceof Something
            r'\.hasOwnProperty\(',              # .hasOwnProperty(
            r'\.filter\(function',              # .filter(function
            r'\.map\(function',                 # .map(function
            r'\.forEach\(function',             # .forEach(function
            r'\.reduce\(function',              # .reduce(function
            r'\?\w+\.\w+:\w+\.\w+',             # ?a.b:c.d (ternary)
        ]
        for js_pattern in js_code_indicators:
            if re.search(js_pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # BASE64 DATA URIs IN CSS - These are NOT secrets!
        # =================================================================
        # Base64 encoded images/fonts in CSS are NOT secrets
        if re.search(r'data:(image|font|application)/(png|jpeg|gif|svg|woff|woff2|ttf|otf|octet-stream)', value_to_check, re.IGNORECASE):
            return True
        # Base64 string that looks like font embedding
        if file_lower.endswith('.css') and re.match(r'^[A-Za-z0-9+/]{50,}={0,2}$', value_to_check):
            return True
        
        # =================================================================
        # CAMELCASE / PASCALCASE IDENTIFIERS - These are NOT secrets!
        # =================================================================
        # Things like "KeyLockProcessing", "UserNameValidation" are code identifiers
        # Real secrets don't look like English words
        if re.match(r'^[A-Z][a-z]+([A-Z][a-z]+)+$', value_to_check):
            # PascalCase with multiple words - likely a code identifier
            return True
        if re.match(r'^[a-z]+([A-Z][a-z]+)+$', value_to_check):
            # camelCase with multiple words - likely a code identifier
            return True
        
        # =================================================================
        # CSS/STYLE DETECTION - These are NOT secrets!
        # =================================================================
        css_indicators = [
            r'font-size\s*:', r'font-weight\s*:', r'font-family\s*:',
            r'color\s*:\s*#[0-9a-fA-F]', r'background-color\s*:',
            r'background\s*:\s*(#|rgba?|url)', r'border\s*:',
            r'border-radius\s*:', r'margin\s*:', r'padding\s*:',
            r'width\s*:\s*\d+', r'height\s*:\s*\d+', r'max-width\s*:',
            r'min-width\s*:', r'max-height\s*:', r'min-height\s*:',
            r'display\s*:\s*(flex|block|inline|none|grid)',
            r'position\s*:\s*(absolute|relative|fixed|static)',
            r'text-align\s*:', r'text-decoration\s*:', r'line-height\s*:',
            r'overflow\s*:', r'z-index\s*:', r'opacity\s*:',
            r'visibility\s*:', r'box-shadow\s*:', r'transition\s*:',
            r'transform\s*:', r'flex\s*:', r'align-items\s*:',
            r'justify-content\s*:', r'letter-spacing\s*:',
            r'vertical-align\s*:', r'list-style-type\s*:',
            r'sans-serif', r'Roboto', r'Helvetica', r'Arial',
            r'pointer-events\s*:', r'box-sizing\s*:',
        ]
        for css_pattern in css_indicators:
            if re.search(css_pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # LOTTIE ANIMATION FILES - JSON with base64 image data
        # =================================================================
        # Detect Lottie animation structure (generic detection)
        if file_path and file_path.endswith('.json'):
            try:
                import json
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5000)  # Read first 5KB to check structure
                    if any(key in content for key in ['"layers"', '"assets"', '"fr"', '"ip"', '"op"']):
                        # Has Lottie animation structure markers
                        return True
            except:
                pass
        
        # =================================================================
        # BASE64-ENCODED IMAGE DATA - These are NOT secrets!
        # =================================================================
        # Detect common image format headers in base64
        base64_image_headers = [
            r'^iVBORw0KGgo',  # PNG header in base64
            r'^/9j/',  # JPEG header in base64
            r'^R0lGOD',  # GIF header in base64
            r'^data:image/',  # Data URI image
            r'^PHN2ZyB',  # SVG header in base64
        ]
        for img_header in base64_image_headers:
            if re.match(img_header, value_to_check):
                return True
        
        # Check if value looks like base64 image data (very long, high entropy)
        if len(value_to_check) > 1000:  # Very long strings
            # Check for base64 character set
            if re.match(r'^[A-Za-z0-9+/=]+$', value_to_check):
                # Sample the string to detect image-like patterns
                sample = value_to_check[:500]
                # Look for common base64 image patterns
                if any(pattern in sample for pattern in ['iVBOR', '/9j/', 'R0lGO', 'AAAA', 'JFIF']):
                    return True
        
        # =================================================================
        # PROGRAMMING IDENTIFIERS - Variable/function names, NOT secrets!
        # =================================================================
        # Detect common identifier patterns (camelCase, CONSTANT_CASE, PascalCase)
        identifier_patterns = [
            r'^[a-z][a-zA-Z0-9]*$',  # camelCase: myVariable
            r'^[A-Z][A-Z0-9_]*$',  # CONSTANT_CASE: MY_CONSTANT
            r'^[A-Z][a-z][a-zA-Z0-9]*$',  # PascalCase: MyClass
            r'^_[a-zA-Z][a-zA-Z0-9]*$',  # _privateVar
            r'^\$[a-zA-Z][a-zA-Z0-9]*$',  # $jqueryVar
        ]
        
        # Check if it's a pure identifier (single word, no special chars)
        if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', value_to_check):
            # It's a valid identifier
            # Skip if it's too long for a typical identifier (likely not a secret)
            if len(value_to_check) > 50:
                return True
            # Skip common identifier patterns
            for pattern in identifier_patterns:
                if re.match(pattern, value_to_check):
                    return True
            
            # Detect compound words (multiple capital letters = compound identifier)
            # Examples: PASSENGERREDUCER, SELECTEDPASSENGER, PASSPORTDATA
            capital_count = sum(1 for c in value_to_check if c.isupper())
            if capital_count >= 3:  # Multiple capitals = compound word
                # Check if it's all capitals (CONSTANT_CASE)
                if value_to_check.isupper():
                    return True
                # Check if it's PascalCase with multiple words
                # Count uppercase transitions (indicates word boundaries)
                transitions = sum(1 for i in range(1, len(value_to_check)) 
                                if value_to_check[i].isupper() and value_to_check[i-1].islower())
                if transitions >= 1:  # Has word boundaries
                    return True
        
        # =================================================================
        # REACT/JAVASCRIPT PATTERNS - Function calls, hooks, assignments
        # =================================================================
        # Detect React hooks and function calls (these contain code, not secrets)
        react_js_patterns = [
            r'^useMemo\(',  # useMemo(
            r'^useCallback\(',  # useCallback(
            r'^useState\(',  # useState(
            r'^useEffect\(',  # useEffect(
            r'\.find\(',  # .find(
            r'\.filter\(',  # .filter(
            r'\.map\(',  # .map(
            r'\.slice\(',  # .slice(
            r'\.concat\(',  # .concat(
            r'Array\(',  # Array(
            r'^i18n\.translate\(',  # i18n.translate(
            r'Validation\w+\.\w+Validation\(',  # ValidationUtil.alphaNumericValidation(
        ]
        for pattern in react_js_patterns:
            if re.search(pattern, value_to_check):
                return True
        
        # Detect variable assignments and destructuring
        # Examples: "(state", "= (data)", "passenger[index];"
        assignment_patterns = [
            r'^\(\s*state',  # (state
            r'=\s*\(\s*\w+\s*\)',  # = (data), = (props)
            r'\[\s*index\s*\]',  # [index]
            r'\[\d+\]',  # [0], [1]
            r'^ownProps\.',  # ownProps.something
            r'^this\.props\.',  # this.props.something
            r'^this\.state\.',  # this.state.something
            r'^formValues\.',  # formValues.something
            r'^state\.form\.',  # state.form.something
            r'^passenger\[',  # passenger[index]
            r'^userProfile\.',  # userProfile.member
            r'^\w+\.\w+\[',  # object.property[
            r'^\[\.\.\.\w+\]',  # [...spread]
            r'\w+\.\w+\(',  # object.method(
            r'^!!\w+',  # !!variable (double negation)
            r'\.\w+;$',  # ends with .property;
            r'\w+\[\w+\];$',  # array[index];
        ]
        for pattern in assignment_patterns:
            if re.search(pattern, value_to_check):
                return True
        
        # Generic code context detection - if it contains programming syntax, it's not a secret
        # Examples: "(passenger:", "element;", "selectedMeals[passengerId];"
        if any(char in value_to_check for char in ['(', '[', '{', ';', '.', '!']):
            # Contains programming syntax
            # Check if it looks like code rather than a URL or path
            if not re.match(r'^https?://', value_to_check):  # Not a URL
                # Count programming indicators
                prog_indicators = sum([
                    '(' in value_to_check,  # Function call
                    '[' in value_to_check,  # Array access
                    '.' in value_to_check and not value_to_check.count('.') > 3,  # Property access (but not IP)
                    ';' in value_to_check,  # Statement terminator
                    '!' in value_to_check,  # Negation
                ])
                if prog_indicators >= 1:  # Has programming syntax
                    return True
        
        # =================================================================
        # HUMAN-READABLE TEXT / i18n STRINGS - UI text, NOT secrets!
        # =================================================================
        # Detect human-readable text that contains spaces and mixed case
        # Examples: "Change Password", "Forget Password", "Şifre Değiştirme"
        if ' ' in value_to_check:
            # Contains spaces - likely human-readable text
            # Check if it looks like a sentence or phrase (mixed case, readable words)
            words = value_to_check.strip().split()
            if len(words) >= 2:  # At least 2 words
                # Check if words start with capital letters (Title Case for UI text)
                capitalized_words = sum(1 for w in words if w and w[0].isupper())
                if capitalized_words >= len(words) - 1:  # Most words capitalized
                    # Looks like UI text: "Change Password", "Save Password"
                    return True
                
                # Check for common UI/i18n patterns
                ui_keywords = [
                    'password', 'login', 'logout', 'sign in', 'sign up', 
                    'register', 'forgot', 'forget', 'remember', 'save',
                    'change', 'reset', 'verify', 'confirm', 'submit',
                    'cancel', 'back', 'next', 'continue', 'finish',
                    'şifre',  # Turkish: password
                    'giriş',  # Turkish: login
                ]
                value_lower = value_to_check.lower()
                if any(keyword in value_lower for keyword in ui_keywords):
                    # Contains UI-related keywords with spaces - likely UI text
                    return True
        
        # Detect i18n constant values (strings that are clearly for display)
        # Pattern: readable text with capital letters, not random strings
        if len(value_to_check) > 5 and len(value_to_check) < 100:
            # Check character composition
            alpha_count = sum(1 for c in value_to_check if c.isalpha())
            space_count = value_to_check.count(' ')
            
            # If it's mostly letters with some spaces, it's likely UI text
            if alpha_count > len(value_to_check) * 0.7 and space_count > 0:
                return True
        
        # =================================================================
        # CONFIGURATION FILE CONTEXT - Test tokens in config files
        # =================================================================
        # Detect if we're in a configuration/constants file (generic detection)
        if file_path:
            config_indicators = ['config', 'constant', 'setting', 'environment', 'env']
            file_lower = file_path.lower()
            if any(indicator in file_lower for indicator in config_indicators):
                # In a config file - check if value looks like a test/placeholder token
                # JWT tokens in config files are often test tokens
                if re.match(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', value_to_check):
                    # JWT token in config file - likely a test token
                    # Check if payload contains test indicators
                    try:
                        import base64
                        payload = value_to_check.split('.')[1]
                        # Add padding if needed
                        payload += '=' * (4 - len(payload) % 4)
                        decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                        if any(test in decoded.lower() for test in ['test', 'dev', 'demo', 'example']):
                            return True
                    except:
                        pass
        
        # =================================================================
        # URL TEMPLATES WITHOUT CREDENTIALS - These are NOT secrets!
        # =================================================================
        # API endpoint templates with placeholders like {startDate}, {legIsn}
        if re.search(r'^\./|^/\w', value_to_check):  # Starts with ./ or /word
            # Check if it's a URL template with placeholders
            if re.search(r'\{[a-zA-Z_][a-zA-Z0-9_.]*(:.*?)?\}', value_to_check):
                # Has placeholders like {startDate:dd.MM.yyyy} - NOT a secret
                # BUT check if it has actual credentials
                if not re.search(r'(password|secret|key|token|auth)=\w+', value_to_check, re.IGNORECASE):
                    return True
        
        # =================================================================
        # CODE EXPRESSIONS - These are NOT secrets!
        # =================================================================
        code_indicators = [
            r'^\s*!!\w+\.',  # !!item.something
            r'\s*&&\s*',  # && operator
            r'\s*\|\|\s*',  # || operator
            r'\.length\s*[><=]',  # .length comparisons
            r'\.indexOf\s*\(',  # .indexOf calls
            r'\.ToString\s*\(',  # .ToString() calls
            r'\.Value\s*[}\]]',  # .Value} or .Value]
            r'\?\s*\w+\s*:',  # ternary operator
            r'^\s*\w+\s*\?\?',  # null coalescing
            r';\s*else\s+\w+',  # ; else something
            r'^\s*preview\s*\|\|',  # Angular template
            r'\bcanAdd\w+\b',  # canAddSomething
            r'^\s*\(\s*!',  # starts with ( !
            r'\$\{[\w.]+\}',  # ${variable} template
            r'\{\{[\w.]+\}\}',  # {{variable}} template
            r'\bstring\.Join\s*\(',  # string.Join(
            r'\bOldValue\s*=',  # OldValue = 
            r'\bNewValue\s*=',  # NewValue =
            r'destination\.\w+\?\.',  # destination.Prop?.
            r'Groups\[\d+\]',  # regex Groups[0]
            r'match\.Groups',  # match.Groups
            # Function parameters and variable assignments (NOT passwords!)
            r'^\s*\(\s*\w+\s*\)$',  # (state), (data), (props)
            r'^\s*\(\s*\w+\s*,$',  # (flight, (data,
            r'^\s*(true|false|null|undefined)\s*;$',  # boolean/null literals
            r'^\s*\w+\.\w+\s*=\s*\(\s*\w+\s*\)',  # func = (data)
            r'^\s*[A-Z_]+\s*$',  # Pure constants: UPDATE_MEMBER_PASSWORD
            r'^\s*get[A-Z]\w+\s*\(',  # getReservedPassengers(
            r'\?\.\w+\?\.\w+',  # optional chaining
            r'\?\.\w+\s*$',  # ends with optional chaining
        ]
        for code_pattern in code_indicators:
            if re.search(code_pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # HTTP SECURITY HEADERS - These are NOT secrets!
        # =================================================================
        header_patterns = [
            r'^max-age=\d+',  # HSTS header
            r'includeSubDomains',
            r'^\s*preload\s*$',
            r'Content-Security-Policy',
            r'X-Frame-Options',
            r'X-Content-Type-Options',
        ]
        for header_pattern in header_patterns:
            if re.search(header_pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # PUBLIC CDN URLs - These are NOT secrets!
        # =================================================================
        public_cdn_domains = [
            r'unpkg\.com/', r'cdnjs\.', r'jsdelivr\.', 
            r'gstatic\.com/', r'googleapis\.com/',
            r'firebaseio\.com[/\s]',  # Firebase URLs without auth
            r'bootstrapcdn\.', r'cloudflare\.com/',
        ]
        # Only exclude if it's a CDN URL without embedded credentials
        if re.search(r'https?://', value_to_check):
            for cdn in public_cdn_domains:
                if re.search(cdn, value_to_check, re.IGNORECASE):
                    # Make sure there's no password/key in the URL
                    if not re.search(r'(password|key|token|secret|auth)=\w{8,}', value_to_check, re.IGNORECASE):
                        return True
        
        # =================================================================
        # STRING MESSAGES / UI TEXT - These are NOT secrets!
        # =================================================================
        # Turkish and common UI text patterns
        ui_text_patterns = [
            r'Pozisyonu\s*\{',  # Turkish: "Park Pozisyonu {var}"
            r'adresine\s+mail',  # Turkish: email message
            r'Lütfen\s+\w+',  # Turkish: "Please..."
            r'Misafirlerimizi',  # Turkish: "Our guests"
            r'gönderilmiştir',  # Turkish: "has been sent"
            r'\\n\s*\*\*\{',  # Markdown with variables
            r'UserName\s*=\s*"[A-Z]+"',  # Hardcoded username like "SISTEM" (not a password)
        ]
        for ui_pattern in ui_text_patterns:
            if re.search(ui_pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # ANGULAR/HTML TEMPLATE EXPRESSIONS - These are NOT secrets!
        # =================================================================
        angular_patterns = [
            r'^\s*\*ngIf\s*=',
            r'^\s*\*ngFor\s*=',
            r'\[ngClass\]',
            r'\(click\)\s*=',
            r'style\s*=\s*["\']?$',  # ends with style="
            r'><span\s+style',  # ><span style
            r'</span><span',  # HTML tags
            r'class\s*=\s*["\']',
            r'\$event\s*,\s*\w+\)',  # Angular event: $event, dg)
            r'\{\{row\.\w+',  # Angular template: {{row.PropertyName
            r'_Changed\s*\(\s*\$event',  # Event handler: _Changed($event
            r'\w+_LegIsn\s*\?',  # Angular conditional: Arrival_LegIsn ?
            r'row\.\w+_\w+\s*\}\}',  # Angular template: row.Arrival_ParkPosition }}
        ]
        for angular_pattern in angular_patterns:
            if re.search(angular_pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # TEST DATA / MOCK VALUES - These are NOT secrets!
        # =================================================================
        test_data_patterns = [
            r'TotalPax\w*\s*=',  # Test passenger data: TotalPaxPassenger =
            r'"182\+80"',  # Hardcoded test value
            r'\d+\s*\+\s*\d+',  # Math expressions like 182+80
            r'margin-bottom\s*:\s*\d+',  # CSS margin
            r'height\s*:\s*calc\(',  # CSS calc()
        ]
        for test_pattern in test_data_patterns:
            if re.search(test_pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # FUNCTION CALLS WITHOUT SECRETS
        # =================================================================
        function_call_patterns = [
            r'^open\w+Modal\s*\(',  # openLoadSheetModal(
            r'^open\w+\s*\(',  # openSomething(
            r'item\.\w+_LegIsn',  # item.Arrival_LegIsn
            r'item\.RegSerial',
        ]
        for fn_pattern in function_call_patterns:
            if re.search(fn_pattern, value_to_check, re.IGNORECASE):
                return True
        
        # =================================================================
        # SIMPLE STRING CONSTANTS - These are NOT secrets!
        # But EXCLUDE known credential prefixes
        # =================================================================
        # Known credential prefixes that should NEVER be filtered
        credential_prefixes = [
            r'^AKIA',  # AWS Access Key
            r'^ABIA',  # AWS
            r'^ACCA',  # AWS
            r'^AGPA',  # AWS
            r'^AIDA',  # AWS
            r'^AIPA',  # AWS
            r'^AKIA',  # AWS
            r'^ANPA',  # AWS
            r'^ANVA',  # AWS
            r'^APKA',  # AWS
            r'^AROA',  # AWS
            r'^ASCA',  # AWS
            r'^ASIA',  # AWS (STS)
            r'^ghp_',  # GitHub PAT
            r'^gho_',  # GitHub OAuth
            r'^ghu_',  # GitHub User
            r'^ghs_',  # GitHub Server
            r'^ghr_',  # GitHub Refresh
            r'^xox[baprs]-',  # Slack tokens
            r'^sk-',  # OpenAI/Stripe
            r'^pk_',  # Stripe public
            r'^rk_',  # Stripe restricted
            r'^AIza',  # Google API
            r'^ya29\.',  # Google OAuth
        ]
        
        # Check if value starts with known credential prefix
        is_known_credential = any(re.match(prefix, value_to_check, re.IGNORECASE) for prefix in credential_prefixes)
        
        # Only apply "simple constant" filtering if NOT a known credential format
        if not is_known_credential:
            if re.match(r'^[A-Za-z][A-Za-z0-9]*$', value_to_check):
                # Single word, no special chars - likely a constant name
                if len(value_to_check) < 30:
                    # Calculate entropy - low entropy = not a secret
                    entropy = self._calculate_entropy(value_to_check)
                    if entropy < 3.5:
                        return True
        
        # =================================================================
        # ORIGINAL CHECKS
        # =================================================================
        
        # 1. Check against false positive patterns (placeholder values, etc.)
        for fp_pattern in self.false_positive_patterns:
            if fp_pattern.search(value_to_check):
                return True
        
        # 2. Check against known public tokens
        for public_token in self.public_tokens:
            if public_token.lower() in value_to_check.lower():
                return True
        
        # 3. Check against exclusion patterns by category
        for category, patterns in self.exclusion_patterns.items():
            for pattern in patterns:
                # Check both the matched value and the full line
                if pattern.search(matched_value) or pattern.search(line):
                    return True
        
        # 4. String format template detection ({0}, {1}, etc.)
        if re.search(r'\{[0-9]+\}', matched_value):
            return True
        
        # 5. XML namespace detection
        if re.search(r'xmlns(:\w+)?=|http://schemas\.|http://www\.w3\.org/', line, re.IGNORECASE):
            return True
        
        # 6. .NET assembly reference detection (including Version= and Culture=)
        if re.search(r'(PublicKeyToken=|Version=\d+\.\d+\.\d+\.\d+|Culture=neutral|\.dll|<Reference\s+Include=|<PackageReference)', line, re.IGNORECASE):
            return True
        
        # 7. Check if in test file
        if re.search(r'(test|spec|mock|fake|stub|fixture)s?[/\\.]', file_path, re.IGNORECASE):
            # Be more lenient with test files - only flag high-entropy actual secrets
            if actual_value:
                entropy = self._calculate_entropy(actual_value)
                if entropy < 3.0:  # Low entropy = likely test data
                    return True
        
        # 8. Check for common placeholder patterns in the value
        placeholder_patterns = [
            r'^(xxx+|yyy+|zzz+)$',
            r'^(your|my|test|sample|example)[_-]?\w*$',
            r'^[<\[{].*[>\]}]$',  # <placeholder>, [value], {token}
            r'^\$\{.*\}$',  # ${VAR}
            r'^\$\([^)]+\)$',  # $(VAR)
            r'^%[A-Z_]+%$',  # %VAR%
            r'^@\w+$',  # @variable
        ]
        for pp in placeholder_patterns:
            if re.match(pp, value_to_check, re.IGNORECASE):
                return True
        
        # 9. Very short values (less than 4 chars) are usually not secrets
        if len(value_to_check) < 4:
            return True
        
        # 10. Check for documentation/comment URLs
        doc_domains = [
            'docs.', 'documentation.', 'api.', 'learn.', 
            'developer.', 'msdn.', 'technet.',
            'stackoverflow.com', 'github.com/.*/(blob|tree)/',
            'wikipedia.org', 'w3schools.com'
        ]
        for domain in doc_domains:
            if re.search(domain, matched_value, re.IGNORECASE):
                return True
        
        return False
    
    def _suggest_env_var(self, secret_type: SecretType, file_path: str) -> str:
        """Suggest an environment variable name based on secret type and file.
        
        All suggested names are prefixed with 'DG_' (DeployGuard) to prevent
        conflicts with existing environment variables.
        """
        type_to_var = {
            SecretType.PASSWORD: "PASSWORD",
            SecretType.DATABASE_PASSWORD: "DB_PASSWORD",
            SecretType.DATABASE_HOST: "DB_HOST",
            SecretType.DATABASE_NAME: "DB_NAME",
            SecretType.DATABASE_USER: "DB_USER",
            SecretType.DATABASE_PORT: "DB_PORT",
            SecretType.API_KEY: "API_KEY",
            SecretType.SECRET_KEY: "SECRET_KEY",
            SecretType.AWS_ACCESS_KEY: "AWS_ACCESS_KEY_ID",
            SecretType.AWS_SECRET_KEY: "AWS_SECRET_ACCESS_KEY",
            SecretType.GITHUB_TOKEN: "GITHUB_TOKEN",
            SecretType.HOSTNAME: "HOST",
            SecretType.IP_ADDRESS: "HOST_IP",
            SecretType.PORT: "PORT",
            SecretType.URL: "API_URL",
            SecretType.USERNAME: "USERNAME",
            SecretType.AUTH_TOKEN: "AUTH_TOKEN",
            SecretType.JWT_TOKEN: "JWT_SECRET",
        }
        
        base_name = type_to_var.get(secret_type, "SECRET")
        
        # Try to extract service name from file path
        from pathlib import Path
        file_stem = Path(file_path).stem.upper()
        if file_stem and file_stem not in ["CONFIG", "SETTINGS", "ENV", "SECRETS", "MAIN"]:
            return f"DG_{file_stem}_{base_name}"
        
        return f"DG_{base_name}"

    def scan_directory(
        self, directory: str, max_files: Optional[int] = None, file_includes: Optional[List[str]] = None, file_excludes: Optional[List[str]] = None
    ) -> Dict[str, List[Finding]]:
        """
        Scan all files in a directory.

        Args:
            directory: Path to directory to scan
            max_files: Maximum number of files to scan (for testing)
            file_includes: File extensions to include (e.g., ['.py', '.js'])
            file_excludes: File extensions to exclude

        Returns:
            Dictionary mapping file paths to their findings
        """
        results: Dict[str, List[Finding]] = {}
        dir_path = Path(directory)

        if not dir_path.exists():
            raise ScanError(f"Directory not found: {directory}")

        files_scanned = 0
        skipped_large = 0
        skipped_binary = 0
        
        for file_path in dir_path.rglob("*"):
            if max_files and files_scanned >= max_files:
                break

            if not file_path.is_file():
                continue
            
            # Skip binary/archive files by extension
            suffix = file_path.suffix.lower()
            if suffix in self.skip_extensions:
                skipped_binary += 1
                continue
            
            # Skip files that are too large
            try:
                file_size = file_path.stat().st_size
                if file_size > self.max_file_size:
                    skipped_large += 1
                    continue
            except OSError:
                continue

            if self._should_exclude_file(str(file_path)):
                continue

            try:
                # Try to read as text
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                findings = self.scan_file(str(file_path.relative_to(dir_path)), content)

                if findings:
                    results[str(file_path.relative_to(dir_path))] = findings

                files_scanned += 1

            except Exception as e:
                # Skip binary files or files with encoding issues
                continue

        return results

    def _should_exclude_file(self, file_path: str) -> bool:
        """Check if file should be excluded from scanning."""
        path = Path(file_path)
        path_str = str(path).replace("\\", "/")  # Normalize path separators
        
        # Check path exclusion patterns from global_allowlists.paths first
        for pattern in self.path_exclusion_patterns:
            if pattern.search(path_str):
                return True
        
        # Always exclude .git directory
        if '/.git/' in path_str or path_str.startswith('.git/') or '/.git' == path_str:
            return True
        
        # Check exclude patterns from file_patterns - these take priority
        for exclude_pattern in self.file_excludes:
            exclude_pattern = exclude_pattern.replace("\\", "/")
            
            # Check if any part of the path contains excluded directories
            if "*" in exclude_pattern:
                # Extract directory names from pattern
                parts = [p for p in exclude_pattern.replace("*", "").split("/") if p]
                path_parts = path_str.split("/")
                # If any excluded directory is in the path, exclude it
                if any(part in path_parts for part in parts):
                    return True
            elif exclude_pattern in path_str:
                return True

        # If no include patterns specified, include by default
        if not self.file_includes:
            return False
            
        # Check include patterns - file must match at least one
        for include_pattern in self.file_includes:
            include_pattern = include_pattern.replace("\\", "/")
            # Use suffix matching for simple patterns like "*.py"
            if include_pattern.startswith("**/"):
                # Match files ending with the pattern
                suffix = include_pattern[3:]  # Remove "**/
                if suffix.startswith("*."):
                    ext = suffix[1:]  # Remove "*", keep ".py"
                    if path_str.endswith(ext):
                        return False
            elif path.match(include_pattern):
                return False
        
        # Didn't match any include pattern
        return True

    def _detect_high_entropy(self, file_path: str, content: str) -> List[Finding]:
        """
        Detect high-entropy strings that might be secrets.

        Args:
            file_path: Path to file being scanned
            content: File content

        Returns:
            List of findings for high-entropy strings
        """
        findings: List[Finding] = []
        lines = content.split("\n")

        # Pattern to find potential string values
        string_pattern = re.compile(r'["\']([^"\']{20,})["\']')
        
        # Patterns to exclude (false positives)
        exclude_patterns = [
            re.compile(r'^(INSERT|UPDATE|DELETE|SELECT|CREATE|ALTER|DROP)\s', re.IGNORECASE),  # SQL statements
            re.compile(r'^https?://', re.IGNORECASE),  # URLs without credentials
            re.compile(r'^gcr\.io/', re.IGNORECASE),  # GCR image paths
            re.compile(r'^docker\.io/', re.IGNORECASE),  # Docker Hub paths
            re.compile(r'^\$[A-Z_]+'),  # Environment variable references
            re.compile(r'^[a-z0-9\-]+\.[a-z]{2,}$', re.IGNORECASE),  # Domain names
            re.compile(r'^/[a-z0-9/_\-]+$', re.IGNORECASE),  # Unix paths
            re.compile(r'^\w+\s+\w+\s+\w+\s+\w+'),  # Regular sentences (4+ words)
            # .NET assembly references
            re.compile(r'PublicKeyToken=', re.IGNORECASE),
            re.compile(r'Version=\d+\.\d+\.\d+\.\d+', re.IGNORECASE),
            re.compile(r'Culture=\w+', re.IGNORECASE),
            re.compile(r'^(System|Microsoft|Newtonsoft)\.[A-Za-z.]+', re.IGNORECASE),
            # XML schemas/namespaces
            re.compile(r'xmlns', re.IGNORECASE),
            re.compile(r'http://schemas\.(xmlsoap|microsoft|openxmlformats)\.', re.IGNORECASE),
            re.compile(r'http://www\.w3\.org/', re.IGNORECASE),
            # Build/project file patterns
            re.compile(r'^\$\([^)]+\)$'),  # $(ProjectDir) MSBuild variables
            re.compile(r'%\([^)]+\)'),  # %(Identity) MSBuild item metadata
        ]
        
        # Skip entropy detection entirely for .NET/XML project files (too many false positives)
        path_lower = file_path.lower()
        if any(ext in path_lower for ext in ['.csproj', '.vbproj', '.fsproj', '.vcxproj', '.props', '.targets', '.config', '.resx', '.settings']):
            return findings
        
        # Skip entropy detection for JS/CSS files (they have high entropy code that's not secrets)
        skip_entropy_patterns = [
            '.min.js', '.min.css', '.bundle.js', '.chunk.js',
            '.css', '.map',  # CSS and source maps
            '/vendor/', '/node_modules/', '/dist/', '/build/',
            'package-lock.json', 'yarn.lock', 'composer.lock',
        ]
        if any(skip in path_lower for skip in skip_entropy_patterns):
            return findings
        
        # Also skip ANY .js file for entropy detection - too many false positives
        # Pattern-based detection will still work for actual API keys in JS
        if path_lower.endswith('.js'):
            return findings

        for line_num, line in enumerate(lines, 1):
            matches = string_pattern.finditer(line)

            for match in matches:
                value = match.group(1)
                
                # Skip if value matches any exclusion pattern
                if any(pattern.search(value) for pattern in exclude_patterns):
                    continue
                
                # Check if this is a false positive using the same logic as pattern detection
                if self._is_false_positive(value, value, line, file_path):
                    continue

                # Calculate Shannon entropy
                entropy = self._calculate_entropy(value)

                if entropy >= self.min_entropy and len(value) >= self.min_length:
                    # Determine severity and type based on context patterns
                    severity, secret_type, description = self._classify_high_entropy_secret(value, line, entropy)
                    
                    finding = Finding(
                        type=secret_type,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        exposed_value=value,
                        exposed_value_hash=self._hash_value(value),
                        description=description,
                        remediation="Review if this is a secret and use environment variables",
                        context=self._extract_context(lines, line_num),
                        metadata={"entropy": entropy},
                    )
                    findings.append(finding)

        return findings
    
    def _classify_high_entropy_secret(self, value: str, line: str, entropy: float) -> Tuple[Severity, SecretType, str]:
        """
        Classify a high-entropy string to determine its severity and type.
        
        Args:
            value: The high-entropy string value
            line: The full line containing the value
            entropy: Calculated entropy value
            
        Returns:
            Tuple of (severity, secret_type, description)
        """
        line_lower = line.lower()
        
        # CRITICAL patterns - real credentials
        critical_patterns = [
            # Firebase/FCM keys
            (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,}', 'fcm', SecretType.API_KEY, 'Firebase Cloud Messaging (FCM) Server Key'),
            # Connection strings with passwords
            (r'password\s*=\s*[^;"\s]+', 'connection_string', SecretType.DATABASE_PASSWORD, 'Database connection string with password'),
            # JWT/signing keys (base64 encoded, typically end with =)
            (r'[A-Za-z0-9+/]{40,}={1,2}$', 'jwt_key', SecretType.SECRET_KEY, 'Base64 encoded key (likely JWT/signing key)'),
            # AWS keys
            (r'AKIA[A-Z0-9]{16}', 'aws', SecretType.AWS_ACCESS_KEY, 'AWS Access Key'),
            # Private keys
            (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'private_key', SecretType.PRIVATE_KEY, 'Private Key'),
            # API keys with common prefixes
            (r'^(sk_live_|pk_live_|rk_live_)', 'stripe', SecretType.API_KEY, 'Stripe API Key'),
            (r'^(ghp_|gho_|ghu_|ghs_|ghr_)', 'github', SecretType.GITHUB_TOKEN, 'GitHub Token'),
            (r'^xox[baprs]-', 'slack', SecretType.AUTH_TOKEN, 'Slack Token'),
        ]
        
        # HIGH patterns - likely credentials
        high_patterns = [
            # Keys in key/secret/token context
            (r'(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)', 'api_context', SecretType.API_KEY, 'API Key or Token'),
            # Server keys
            (r'server[_-]?key', 'server_key', SecretType.API_KEY, 'Server Key'),
            # Signing keys
            (r'(signing[_-]?key|encryption[_-]?key)', 'signing_key', SecretType.SECRET_KEY, 'Signing/Encryption Key'),
            # Bearer tokens
            (r'bearer\s+[a-z0-9._-]+', 'bearer', SecretType.AUTH_TOKEN, 'Bearer Token'),
            # Passwords in context
            (r'(passwd|pwd)\s*[=:]', 'password', SecretType.PASSWORD, 'Password'),
        ]
        
        # Check CRITICAL patterns first (on the value itself)
        for pattern, _, secret_type, desc in critical_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return Severity.CRITICAL, secret_type, f'{desc} detected (entropy: {entropy:.2f})'
        
        # Check CRITICAL patterns on line context
        for pattern, _, secret_type, desc in critical_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return Severity.CRITICAL, secret_type, f'{desc} detected (entropy: {entropy:.2f})'
        
        # Check HIGH patterns on line context
        for pattern, _, secret_type, desc in high_patterns:
            if re.search(pattern, line_lower):
                return Severity.HIGH, secret_type, f'{desc} detected (entropy: {entropy:.2f})'
        
        # Very high entropy (>5.5) with long strings (>50 chars) are more likely real secrets
        if entropy > 5.5 and len(value) > 50:
            return Severity.HIGH, SecretType.GENERIC_SECRET, f'High entropy string detected (entropy: {entropy:.2f})'
        
        # Default to MEDIUM for generic high entropy
        return Severity.MEDIUM, SecretType.GENERIC_SECRET, f'High entropy string detected (entropy: {entropy:.2f})'

    def _calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            data: String to analyze

        Returns:
            Entropy value (higher = more random)
        """
        if not data:
            return 0.0

        # Count character frequencies
        frequencies: Dict[str, int] = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        length = len(data)

        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _hash_value(self, value: str) -> str:
        """Create a hash of the exposed value for tracking."""
        return hashlib.sha256(value.encode()).hexdigest()

    def _extract_context(self, lines: List[str], line_number: int, context_size: int = 2) -> str:
        """
        Extract surrounding lines for context.

        Args:
            lines: All lines in the file
            line_number: Line number of the finding (1-indexed)
            context_size: Number of lines before/after to include

        Returns:
            Context string with surrounding lines
        """
        start = max(0, line_number - context_size - 1)
        end = min(len(lines), line_number + context_size)

        context_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            context_lines.append(f"{prefix}{i + 1:4d} | {lines[i]}")

        return "\n".join(context_lines)

    def generate_variable_name(
        self, secret_type: SecretType, existing_vars: Set[str]
    ) -> str:
        """
        Generate a semantic environment variable name.
        
        All names are prefixed with 'DG_' (DeployGuard) to prevent
        conflicts with existing environment variables.

        Args:
            secret_type: Type of secret
            existing_vars: Set of existing variable names to avoid conflicts

        Returns:
            Unique variable name with DG_ prefix
        """
        base_names = {
            SecretType.AWS_ACCESS_KEY: "AWS_ACCESS_KEY_ID",
            SecretType.AWS_SECRET_KEY: "AWS_SECRET_ACCESS_KEY",
            SecretType.GITHUB_TOKEN: "GITHUB_TOKEN",
            SecretType.GITLAB_TOKEN: "GITLAB_TOKEN",
            SecretType.BITBUCKET_TOKEN: "BITBUCKET_TOKEN",
            SecretType.DATABASE_CONNECTION: "DATABASE_URL",
            SecretType.PRIVATE_KEY: "PRIVATE_KEY",
            SecretType.SSH_KEY: "SSH_PRIVATE_KEY",
            SecretType.API_KEY: "API_KEY",
            SecretType.PASSWORD: "PASSWORD",
            SecretType.JWT_TOKEN: "JWT_SECRET",
            SecretType.OAUTH_SECRET: "OAUTH_CLIENT_SECRET",
            SecretType.ENCRYPTION_KEY: "ENCRYPTION_KEY",
            SecretType.GENERIC_SECRET: "SECRET_VALUE",
        }

        base_name = f"DG_{base_names.get(secret_type, 'SECRET_VALUE')}"

        # If no conflict, return base name
        if base_name not in existing_vars:
            return base_name

        # Add numeric suffix to avoid conflicts
        counter = 1
        while f"{base_name}_{counter}" in existing_vars:
            counter += 1

        return f"{base_name}_{counter}"
