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


class SecretScanner:
    """
    Scans code for exposed secrets using pattern matching and entropy analysis.

    This class implements the core secret detection engine with support for:
    - Regex pattern matching
    - Entropy-based detection
    - File filtering
    - Context extraction
    """

    def __init__(self, patterns_file: Optional[str] = None):
        """
        Initialize the secret scanner.

        Args:
            patterns_file: Path to YAML file with secret patterns
        """
        self.patterns: List[SecretPattern] = []
        self.file_includes: List[str] = []
        self.file_excludes: List[str] = []
        self.entropy_enabled: bool = True
        self.min_entropy: float = 4.5
        self.min_length: int = 20

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

                finding = Finding(
                    type=pattern.secret_type,
                    severity=pattern.severity,
                    file_path=file_path,
                    line_number=line_number,
                    column_start=column_start,
                    column_end=column_start + len(match.group(0)),
                    exposed_value=match.group(0),
                    exposed_value_hash=self._hash_value(actual_value or match.group(0)),
                    suggested_variable=variable_name or self._suggest_env_var(pattern.secret_type, file_path),
                    description=pattern.description,
                    remediation=pattern.remediation,
                    context=self._extract_context(lines, line_number),
                    metadata={
                        "variable_name": variable_name,
                        "actual_value": actual_value,
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
        
        Args:
            full_match: The full matched string
            groups: Captured groups from the regex
            
        Returns:
            Tuple of (variable_name, actual_value)
        """
        variable_name = None
        actual_value = None
        
        # Try to parse assignment patterns: VAR=value or VAR="value"
        assignment_pattern = re.compile(
            r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["\']?(.+?)["\']?$',
            re.IGNORECASE
        )
        
        match = assignment_pattern.match(full_match.strip())
        if match:
            variable_name = match.group(1).upper()
            actual_value = match.group(2)
        elif groups:
            # Use captured groups
            for group in groups:
                if group:
                    # First non-empty group with letters is likely the variable name
                    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', str(group)):
                        if not variable_name:
                            variable_name = str(group).upper()
                    else:
                        # Otherwise it's likely the value
                        if not actual_value:
                            actual_value = str(group)
        
        return variable_name, actual_value
    
    def _suggest_env_var(self, secret_type: SecretType, file_path: str) -> str:
        """Suggest an environment variable name based on secret type and file."""
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
            return f"{file_stem}_{base_name}"
        
        return base_name

    def scan_directory(
        self, directory: str, max_files: Optional[int] = None
    ) -> Dict[str, List[Finding]]:
        """
        Scan all files in a directory.

        Args:
            directory: Path to directory to scan
            max_files: Maximum number of files to scan (for testing)

        Returns:
            Dictionary mapping file paths to their findings
        """
        results: Dict[str, List[Finding]] = {}
        dir_path = Path(directory)

        if not dir_path.exists():
            raise ScanError(f"Directory not found: {directory}")

        files_scanned = 0
        for file_path in dir_path.rglob("*"):
            if max_files and files_scanned >= max_files:
                break

            if not file_path.is_file():
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
        
        # Check exclude patterns first - these take priority
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
        ]

        for line_num, line in enumerate(lines, 1):
            matches = string_pattern.finditer(line)

            for match in matches:
                value = match.group(1)
                
                # Skip if value matches any exclusion pattern
                if any(pattern.search(value) for pattern in exclude_patterns):
                    continue

                # Calculate Shannon entropy
                entropy = self._calculate_entropy(value)

                if entropy >= self.min_entropy and len(value) >= self.min_length:
                    # Likely a secret based on high entropy
                    finding = Finding(
                        type=SecretType.GENERIC_SECRET,
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        exposed_value=value,
                        exposed_value_hash=self._hash_value(value),
                        description=f"High entropy string detected (entropy: {entropy:.2f})",
                        remediation="Review if this is a secret and use environment variables",
                        context=self._extract_context(lines, line_num),
                        metadata={"entropy": entropy},
                    )
                    findings.append(finding)

        return findings

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

        Args:
            secret_type: Type of secret
            existing_vars: Set of existing variable names to avoid conflicts

        Returns:
            Unique variable name
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

        base_name = base_names.get(secret_type, "SECRET_VALUE")

        # If no conflict, return base name
        if base_name not in existing_vars:
            return base_name

        # Add numeric suffix to avoid conflicts
        counter = 1
        while f"{base_name}_{counter}" in existing_vars:
            counter += 1

        return f"{base_name}_{counter}"
