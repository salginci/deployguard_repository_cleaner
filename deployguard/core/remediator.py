"""
DeployGuard Code Remediation Module

Automatically replaces hardcoded secrets with environment variable references.
Supports multiple programming languages and configuration file formats.
"""
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from enum import Enum


class Language(str, Enum):
    """Supported programming languages and file types."""
    BASH = "bash"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUBY = "ruby"
    PHP = "php"
    CSHARP = "csharp"
    YAML = "yaml"
    JSON = "json"
    PROPERTIES = "properties"
    INI = "ini"
    DOCKERFILE = "dockerfile"
    UNKNOWN = "unknown"


@dataclass
class ReplacementResult:
    """Result of a code replacement operation."""
    file_path: str
    original_line: str
    new_line: str
    line_number: int
    variable_name: str
    old_value: str
    success: bool = True
    error: Optional[str] = None


@dataclass 
class RemediationResult:
    """Result of the full remediation process."""
    files_modified: int = 0
    replacements_made: int = 0
    env_file_created: bool = False
    env_file_path: Optional[str] = None
    replacements: List[ReplacementResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class CodeRemediator:
    """
    Replaces hardcoded secrets with environment variable references.
    
    Supports language-specific replacement patterns:
    - Bash: VAR=$VAR or VAR=${VAR}
    - Python: os.environ.get('VAR') or os.getenv('VAR')
    - JavaScript/TypeScript: process.env.VAR
    - Java: System.getenv("VAR")
    - Go: os.Getenv("VAR")
    - Ruby: ENV['VAR']
    - PHP: $_ENV['VAR'] or getenv('VAR')
    - YAML/JSON: ${VAR} (for Docker Compose, K8s, etc.)
    """
    
    # File extension to language mapping
    EXTENSION_MAP = {
        ".sh": Language.BASH,
        ".bash": Language.BASH,
        ".zsh": Language.BASH,
        ".py": Language.PYTHON,
        ".js": Language.JAVASCRIPT,
        ".jsx": Language.JAVASCRIPT,
        ".ts": Language.TYPESCRIPT,
        ".tsx": Language.TYPESCRIPT,
        ".java": Language.JAVA,
        ".go": Language.GO,
        ".rb": Language.RUBY,
        ".php": Language.PHP,
        ".cs": Language.CSHARP,
        ".yaml": Language.YAML,
        ".yml": Language.YAML,
        ".json": Language.JSON,
        ".properties": Language.PROPERTIES,
        ".ini": Language.INI,
        ".env": Language.BASH,
        "Dockerfile": Language.DOCKERFILE,
    }
    
    def __init__(self, dry_run: bool = True):
        """
        Initialize the remediator.
        
        Args:
            dry_run: If True, don't actually modify files (just show what would change)
        """
        self.dry_run = dry_run
    
    def detect_language(self, file_path: str) -> Language:
        """Detect the programming language from file extension."""
        path = Path(file_path)
        
        # Check filename first (for Dockerfile, Makefile, etc.)
        if path.name in self.EXTENSION_MAP:
            return self.EXTENSION_MAP[path.name]
        
        # Check extension
        ext = path.suffix.lower()
        return self.EXTENSION_MAP.get(ext, Language.UNKNOWN)
    
    def get_env_var_syntax(
        self, 
        language: Language, 
        var_name: str,
        context: str = "",
    ) -> str:
        """
        Get the appropriate environment variable syntax for a language.
        
        Args:
            language: The programming language
            var_name: The environment variable name
            context: The surrounding code context (helps determine best syntax)
            
        Returns:
            The appropriate env var reference syntax
        """
        syntax_map = {
            Language.BASH: f"${{{var_name}}}",
            Language.PYTHON: f"os.environ.get('{var_name}')",
            Language.JAVASCRIPT: f"process.env.{var_name}",
            Language.TYPESCRIPT: f"process.env.{var_name}",
            Language.JAVA: f'System.getenv("{var_name}")',
            Language.GO: f'os.Getenv("{var_name}")',
            Language.RUBY: f"ENV['{var_name}']",
            Language.PHP: f"getenv('{var_name}')",
            Language.CSHARP: f'Environment.GetEnvironmentVariable("{var_name}")',
            Language.YAML: f"${{{var_name}}}",
            Language.JSON: f"${{{var_name}}}",  # For docker-compose, etc.
            Language.PROPERTIES: f"${{{var_name}}}",
            Language.INI: f"${{{var_name}}}",
            Language.DOCKERFILE: f"${{{var_name}}}",
            Language.UNKNOWN: f"${{{var_name}}}",  # Default to shell-like syntax
        }
        
        return syntax_map.get(language, f"${{{var_name}}}")
    
    def get_env_var_syntax_for_assignment(
        self,
        language: Language,
        var_name: str,
        original_line: str,
    ) -> Tuple[str, str]:
        """
        Get the full line replacement for an assignment statement.
        
        Args:
            language: The programming language
            var_name: The environment variable name
            original_line: The original line of code
            
        Returns:
            Tuple of (new_line, import_statement_if_needed)
        """
        import_needed = ""
        
        if language == Language.BASH:
            # export VAR="value" -> export VAR="${VAR}"
            # VAR="value" -> VAR="${VAR}"
            pattern = rf'({var_name}\s*=\s*)["\']?[^"\']*["\']?'
            new_line = re.sub(pattern, rf'\1"${{{var_name}}}"', original_line)
            
        elif language == Language.PYTHON:
            # var = "value" -> var = os.environ.get('VAR')
            # Need to add: import os
            pattern = rf'(\s*{var_name.lower()}\s*=\s*)["\'][^"\']*["\']'
            new_line = re.sub(
                pattern, 
                rf"\1os.environ.get('{var_name}')", 
                original_line,
                flags=re.IGNORECASE
            )
            import_needed = "import os"
            
        elif language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            # const var = "value" -> const var = process.env.VAR
            pattern = rf'((?:const|let|var)?\s*\w+\s*=\s*)["\'][^"\']*["\']'
            new_line = re.sub(pattern, rf'\1process.env.{var_name}', original_line)
            
        elif language == Language.JAVA:
            # String var = "value" -> String var = System.getenv("VAR")
            pattern = rf'(\s*\w+\s+\w+\s*=\s*)["\'][^"\']*["\']'
            new_line = re.sub(pattern, rf'\1System.getenv("{var_name}")', original_line)
            
        elif language == Language.GO:
            # var := "value" -> var := os.Getenv("VAR")
            pattern = rf'(\s*\w+\s*:?=\s*)["\'][^"\']*["\']'
            new_line = re.sub(pattern, rf'\1os.Getenv("{var_name}")', original_line)
            import_needed = '"os"'
            
        elif language == Language.RUBY:
            # var = "value" -> var = ENV['VAR']
            pattern = rf'(\s*\w+\s*=\s*)["\'][^"\']*["\']'
            new_line = re.sub(pattern, rf"\1ENV['{var_name}']", original_line)
            
        elif language == Language.PHP:
            # $var = "value" -> $var = getenv('VAR')
            pattern = rf'(\s*\$\w+\s*=\s*)["\'][^"\']*["\']'
            new_line = re.sub(pattern, rf"\1getenv('{var_name}')", original_line)
            
        elif language in (Language.YAML, Language.DOCKERFILE, Language.PROPERTIES, Language.INI):
            # VAR: "value" -> VAR: "${VAR}"
            # VAR=value -> VAR=${VAR}
            pattern = rf'({var_name}\s*[:=]\s*)["\']?[^"\':\n]*["\']?'
            new_line = re.sub(pattern, rf'\1"${{{var_name}}}"', original_line, flags=re.IGNORECASE)
            
        else:
            # Default: replace value with ${VAR}
            pattern = rf'({var_name}\s*[:=]\s*)["\']?[^"\':\n]*["\']?'
            new_line = re.sub(pattern, rf'\1"${{{var_name}}}"', original_line, flags=re.IGNORECASE)
        
        return new_line, import_needed
    
    def replace_in_file(
        self,
        file_path: str,
        line_number: int,
        var_name: str,
        old_value: str,
    ) -> ReplacementResult:
        """
        Replace a hardcoded value with an environment variable reference.
        
        Args:
            file_path: Path to the file to modify
            line_number: Line number (1-indexed) where the replacement should occur
            var_name: The environment variable name to use
            old_value: The old hardcoded value to replace
            
        Returns:
            ReplacementResult with details of the operation
        """
        try:
            # Read file
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            if line_number < 1 or line_number > len(lines):
                return ReplacementResult(
                    file_path=file_path,
                    original_line="",
                    new_line="",
                    line_number=line_number,
                    variable_name=var_name,
                    old_value=old_value,
                    success=False,
                    error=f"Line {line_number} out of range (file has {len(lines)} lines)"
                )
            
            original_line = lines[line_number - 1]
            language = self.detect_language(file_path)
            
            # Get the replacement
            new_line, import_needed = self.get_env_var_syntax_for_assignment(
                language, var_name, original_line
            )
            
            result = ReplacementResult(
                file_path=file_path,
                original_line=original_line.rstrip('\n'),
                new_line=new_line.rstrip('\n'),
                line_number=line_number,
                variable_name=var_name,
                old_value=old_value,
                success=True,
            )
            
            # Only modify if not dry run and line actually changed
            if not self.dry_run and new_line != original_line:
                lines[line_number - 1] = new_line if new_line.endswith('\n') else new_line + '\n'
                
                with open(file_path, 'w') as f:
                    f.writelines(lines)
            
            return result
            
        except Exception as e:
            return ReplacementResult(
                file_path=file_path,
                original_line="",
                new_line="",
                line_number=line_number,
                variable_name=var_name,
                old_value=old_value,
                success=False,
                error=str(e)
            )
    
    def create_env_file(
        self,
        variables: Dict[str, str],
        output_path: str,
        append: bool = False,
    ) -> str:
        """
        Create or update a .env file with the actual secret values.
        
        Args:
            variables: Dictionary of {VAR_NAME: actual_value}
            output_path: Path to the .env file
            append: If True, append to existing file
            
        Returns:
            Path to the created file
        """
        mode = 'a' if append else 'w'
        
        if not self.dry_run:
            with open(output_path, mode) as f:
                if not append:
                    f.write("# Environment Variables\n")
                    f.write("# Generated by DeployGuard Repository Cleaner\n")
                    f.write("# WARNING: This file contains sensitive values - do NOT commit!\n\n")
                
                for var_name, value in variables.items():
                    # Escape special characters in the value
                    escaped_value = value.replace('"', '\\"')
                    f.write(f'{var_name}="{escaped_value}"\n')
        
        return output_path
    
    def remediate_findings(
        self,
        findings: List[dict],
        base_path: str,
        env_file_path: Optional[str] = None,
    ) -> RemediationResult:
        """
        Remediate all selected findings by replacing hardcoded values.
        
        Args:
            findings: List of finding dictionaries with:
                - file_path: Path to file
                - line_number: Line number
                - variable_name: Suggested variable name
                - actual_value: The hardcoded value
            base_path: Base path for file paths (if relative)
            env_file_path: Path for the .env file (default: base_path/.env)
            
        Returns:
            RemediationResult with all operations
        """
        result = RemediationResult()
        env_vars: Dict[str, str] = {}
        modified_files = set()
        
        for finding in findings:
            file_path = finding.get('file_path', '')
            if not os.path.isabs(file_path):
                file_path = os.path.join(base_path, file_path)
            
            line_number = finding.get('line_number', 0)
            var_name = finding.get('variable_name') or finding.get('suggested_env_var', 'SECRET')
            actual_value = finding.get('actual_value') or finding.get('full_match', '')
            
            # Perform the replacement
            replacement = self.replace_in_file(
                file_path=file_path,
                line_number=line_number,
                var_name=var_name,
                old_value=actual_value,
            )
            
            result.replacements.append(replacement)
            
            if replacement.success:
                result.replacements_made += 1
                modified_files.add(file_path)
                env_vars[var_name] = actual_value
            else:
                result.errors.append(f"{file_path}:{line_number} - {replacement.error}")
        
        result.files_modified = len(modified_files)
        
        # Create .env file
        if env_vars:
            env_path = env_file_path or os.path.join(base_path, '.env')
            self.create_env_file(env_vars, env_path)
            result.env_file_created = True
            result.env_file_path = env_path
        
        return result


def get_language_import_statement(language: Language) -> Optional[str]:
    """Get the import statement needed for env var access in each language."""
    imports = {
        Language.PYTHON: "import os",
        Language.GO: 'import "os"',
        Language.CSHARP: "using System;",
    }
    return imports.get(language)


def format_remediation_preview(result: RemediationResult) -> str:
    """Format a preview of what remediation will do."""
    lines = []
    lines.append("\n" + "=" * 70)
    lines.append("REMEDIATION PREVIEW")
    lines.append("=" * 70)
    
    for replacement in result.replacements:
        if replacement.success:
            lines.append(f"\n📄 {replacement.file_path}:{replacement.line_number}")
            lines.append(f"   Variable: {replacement.variable_name}")
            lines.append(f"   Before: {replacement.original_line}")
            lines.append(f"   After:  {replacement.new_line}")
        else:
            lines.append(f"\n❌ {replacement.file_path}:{replacement.line_number}")
            lines.append(f"   Error: {replacement.error}")
    
    lines.append("\n" + "-" * 70)
    lines.append(f"Files to modify: {result.files_modified}")
    lines.append(f"Replacements: {result.replacements_made}")
    if result.env_file_path:
        lines.append(f"Env file: {result.env_file_path}")
    
    return "\n".join(lines)
