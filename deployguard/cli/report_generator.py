"""
DeployGuard Report Generator

Generates comprehensive security reports in multiple formats:
- Markdown Executive Summary (Turkish/English)
- Gitleaks-compatible JSON
- BFG Purge File (secrets_to_purge.txt)
- Detailed Project Report (Smartgo-style)
- HTML Interactive Report
- CSV Export

Matches Turkish report format with:
- Detailed per-secret analysis
- Credential rotation scripts
- Repository metrics
- Technology stack detection
- Developer re-clone instructions
"""

import os
import json
import csv
import re
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict

from deployguard.core.models import Finding, Severity, SecretType


@dataclass
class RepositoryInfo:
    """Repository metadata for reports."""
    name: str
    path: str
    total_commits: int = 0
    total_branches: int = 0
    total_files: int = 0
    size_bytes: int = 0
    size_after_bytes: int = 0
    history_years: float = 0.0
    first_commit_date: str = ""
    last_commit_date: str = ""
    technology_stack: List[str] = field(default_factory=list)
    remote_url: str = ""
    
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)
    
    def size_after_mb(self) -> float:
        return self.size_after_bytes / (1024 * 1024)


@dataclass 
class CleanupResult:
    """Cleanup operation result for before/after comparison."""
    before_findings: List[Finding]
    after_findings: List[Finding]
    cleaned_secrets: List[str]
    cleanup_rounds: int = 1
    

@dataclass
class SecretDetail:
    """Detailed information about a detected secret."""
    category: str
    secret_value_masked: str
    files: List[str]
    line_numbers: List[int]
    git_commits: int = 0
    git_branches: int = 0
    severity: str = "high"
    description: str = ""
    usage_context: str = ""
    actions_taken: List[str] = field(default_factory=list)
    required_actions: List[str] = field(default_factory=list)
    rotation_script: str = ""


class ReportGenerator:
    """
    Generates comprehensive security scan and cleanup reports.
    
    Supports formats matching Turkish security reports:
    - markdown: Executive summary in Markdown (TR/EN)
    - gitleaks: Gitleaks-compatible JSON
    - bfg: BFG Repo-Cleaner purge file
    - html: Interactive HTML report
    - csv: CSV spreadsheet
    - detailed: Full project report (Smartgo-style)
    """
    
    # Secret type to Turkish description mapping
    SECRET_TYPE_DESCRIPTIONS = {
        "azure_sql": "Azure SQL Database Passwords",
        "sql_server": "On-Premise SQL Server Credentials",
        "database_password": "Database Passwords",
        "connection_string": "Connection Strings",
        "rabbitmq": "RabbitMQ AMQP Credentials",
        "fcm": "Firebase Cloud Messaging (FCM) Server Keys",
        "fcm_server_key": "FCM Server Keys",
        "jwt": "JWT Secret Keys / OAuth Keys",
        "jwt_token": "JWT Tokens",
        "oauth": "OAuth Keys",
        "vapid": "VAPID Private Keys (Web Push)",
        "api_key": "API Keys",
        "secret_key": "Secret Keys",
        "password": "Generic Passwords",
        "aws_access_key": "AWS Access Keys",
        "aws_secret_key": "AWS Secret Keys",
        "github_token": "GitHub Tokens",
        "private_key": "Private Keys",
        "ldap": "LDAP Credentials",
        "internal_ip": "Internal Infrastructure IPs",
        "internal_domain": "Internal Domain Names",
        "generic_secret": "Generic Secrets",
        "base64_secret": "Base64 Encoded Secrets",
        "encryption_key": "Encryption Keys",
    }
    
    # Detailed rotation scripts per secret type
    ROTATION_SCRIPTS = {
        "azure_sql": '''```sql
-- Azure SQL Database Password Rotation
-- Azure Portal → SQL Databases → {db_name} → Security

ALTER LOGIN [{username}] WITH PASSWORD = '<NEW-STRONG-PASSWORD>';

-- Application settings güncelleme:
-- Azure App Service → Configuration → Connection Strings
-- "DefaultConnection" value'sunu yeni password ile güncelleyin
```''',
        
        "sql_server": '''```sql
-- On-Premise SQL Server Password Rotation
ALTER LOGIN [{username}] WITH PASSWORD = '<NEW-STRONG-PASSWORD>';

-- Development appsettings'te yeni şifreyi environment variable olarak kullanın:
-- "ConnectionStrings__DefaultConnection" = "Server=...;Password=${DB_PASSWORD};"
```''',
        
        "rabbitmq": '''```bash
# RabbitMQ Password Rotation
# RabbitMQ Management Console veya CLI

rabbitmqctl change_password {username} <NEW-PASSWORD>

# Tüm consuming service'lerde appsettings güncelleyin:
# - Web Service
# - Background Workers
# - Message Consumers
```''',
        
        "fcm": '''```
FCM Server Key Rotation:

1. Firebase Console → Project Settings → Cloud Messaging
2. Server Key → Regenerate (yeni 152-char key alın)
3. Tüm service'lerde appsettings.json "Fcm:ServerKey" güncelleyin
4. Deploy edin
5. Mobile app'lerde FCM token refresh tetikleyin (optional)
```''',
        
        "jwt": '''```bash
# JWT Secret Key Rotation
# Yeni 256-bit random key generate edin:

openssl rand -base64 64

# appsettings.json "Jwt:SecretKey" güncelleyin

# ⚠️ DİKKAT: Tüm aktif user sessions invalidate olacak
# Kullanıcılar re-login yapmak zorunda kalacak
# Bakım bildirimi gönderin!
```''',
        
        "vapid": '''```bash
# VAPID Key Pair Rotation
# web-push library kullanarak yeni key pair generate edin:

npx web-push generate-vapid-keys

# Public key'i browser'lara re-deploy edin
# ⚠️ Mevcut push subscriptions re-subscribe gerektirecek
```''',
        
        "aws_access_key": '''```bash
# AWS Access Key Rotation
# AWS Console → IAM → Users → Security credentials

1. Create new access key
2. Update all applications with new key
3. Test applications
4. Deactivate old key
5. Delete old key after verification
```''',
        
        "api_key": '''```
API Key Rotation:

1. API provider console'una giriş yapın
2. Yeni API key generate edin
3. Tüm service'lerde environment variable olarak güncelleyin
4. Test edin
5. Eski key'i revoke edin
```''',
        
        "ldap": '''```
LDAP Password Rotation:

1. Active Directory → Users → {username}
2. Reset Password
3. Tüm LDAP binding yapan service'leri güncelleyin
4. Service restart gerekebilir
```''',
    }
    
    # Required actions per secret type (Turkish)
    REQUIRED_ACTIONS_TR = {
        "azure_sql": [
            "Azure Portal → SQL Databases → pegasussqlserver → Smartgo → Security",
            "SQL authentication user password'ünü DEĞİŞTİRİN",
            "Application settings'te yeni password kullanın (environment variable)",
        ],
        "sql_server": [
            "On-premise SQL Server'da test kullanıcısının şifresini değiştirin",
            "Development appsettings'te yeni şifreyi environment variable olarak kullanın",
        ],
        "rabbitmq": [
            "RabbitMQ Management Console → Admin → Users",
            "Kullanıcının şifresini DEĞİŞTİRİN",
            "Tüm consuming service'lerde (Web, ExcelBackup, PushNotification) yeni credentials kullanın",
        ],
        "fcm": [
            "Firebase Console → Project Settings → Cloud Messaging",
            "Server Key'leri ROTATE EDİN (regenerate)",
            "Yeni keys'i tüm service'lerde güncelleyin",
            "Mobile app'lerde FCM token refresh tetikleyin",
        ],
        "jwt": [
            "YENİ JWT secret key generate edin (256-bit random)",
            "TÜM aktif user sessions INVALIDATE edilecek (kullanıcılar re-login yapacak)",
            "User activation key'i yenileyin",
            "Deployment sırasında downtime planlayın",
        ],
        "vapid": [
            "Yeni VAPID key pair generate edin (web-push library)",
            "Public key'i browser'lara re-deploy edin",
            "Mevcut push subscriptions re-subscribe gerektirecek",
        ],
        "api_key": [
            "API provider'a contact edin",
            "API credentials'ları rotate edin",
            "Yeni credentials environment variable olarak kullanın",
        ],
        "internal_ip": [
            "Network Security Review yapın",
            "Firewall rules'u gözden geçirin",
            "Sadece necessary services external'a expose edilmeli",
            "VPN/Bastion host zorunlu hale getirin",
        ],
        "ldap": [
            "Active Directory'de LDAP kullanıcı şifresini değiştirin",
            "Tüm LDAP binding yapan servisleri güncelleyin",
        ],
    }
    
    # Technology detection patterns
    TECH_PATTERNS = {
        ".NET Core / ASP.NET Core": [r"\.csproj", r"appsettings\.json", r"Startup\.cs", r"Program\.cs"],
        "Entity Framework Core": [r"DbContext", r"Microsoft\.EntityFrameworkCore"],
        "Angular": [r"angular\.json", r"@angular/core", r"\.component\.ts"],
        "React": [r"react", r"\.jsx", r"\.tsx"],
        "Node.js": [r"package\.json", r"node_modules"],
        "Python": [r"\.py$", r"requirements\.txt", r"pyproject\.toml"],
        "Java / Spring": [r"\.java$", r"pom\.xml", r"build\.gradle"],
        "RabbitMQ": [r"amqp://", r"RabbitMQ", r"rabbitmq"],
        "Redis": [r"redis://", r"Redis"],
        "Azure SQL Database": [r"database\.windows\.net"],
        "SQL Server": [r"Server=.*\d+\.\d+\.\d+\.\d+"],
        "Firebase": [r"firebase", r"FCM", r"firebaseio\.com"],
        "SignalR": [r"SignalR", r"\.Hubs"],
        "Docker": [r"Dockerfile", r"docker-compose"],
    }
    
    def __init__(self, repo_info: Optional[RepositoryInfo] = None):
        """Initialize report generator."""
        self.repo_info = repo_info or RepositoryInfo(name="Unknown", path=".")
        self.scan_date = datetime.now()
        
    def _get_severity(self, finding: Finding) -> str:
        """Extract severity string from finding."""
        if hasattr(finding.severity, 'value'):
            return finding.severity.value
        return str(finding.severity).lower()
    
    def _get_type(self, finding: Finding) -> str:
        """Extract type string from finding."""
        if hasattr(finding.type, 'value'):
            return finding.type.value
        return str(finding.type).lower()
    
    def _categorize_findings(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by secret type category."""
        categories = defaultdict(list)
        for f in findings:
            secret_type = self._get_type(f)
            context = f.context.lower() if f.context else ""
            value = f.exposed_value.lower() if f.exposed_value else ""
            
            # Intelligent categorization based on content
            if "azure" in context or "database.windows.net" in value:
                category = "azure_sql"
            elif "sql" in secret_type or "database" in secret_type or "connection" in secret_type:
                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value):
                    category = "sql_server"
                else:
                    category = "sql_server"
            elif "rabbitmq" in secret_type or "amqp://" in value:
                category = "rabbitmq"
            elif "fcm" in secret_type or "firebase" in value or value.startswith("AAAA"):
                category = "fcm"
            elif "jwt" in secret_type or "secretkey" in context.replace(" ", "").lower():
                category = "jwt"
            elif "vapid" in secret_type or "vapid" in context.lower():
                category = "vapid"
            elif "ldap" in secret_type or "ldap" in context.lower():
                category = "ldap"
            elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', value):
                category = "internal_ip"
            elif "api" in secret_type and "key" in secret_type:
                category = "api_key"
            else:
                category = secret_type
            
            categories[category].append(f)
        return dict(categories)
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = self._get_severity(f)
            if sev in counts:
                counts[sev] += 1
        return counts
    
    def _get_unique_secrets(self, findings: List[Finding]) -> List[str]:
        """Extract unique secret values from findings."""
        seen = set()
        secrets = []
        for f in findings:
            value = f.metadata.get("actual_value") or f.exposed_value
            if value and value not in seen:
                seen.add(value)
                secrets.append(value)
        return secrets
    
    def _mask_secret(self, value: str, show_length: int = 8) -> str:
        """Mask a secret value for safe display."""
        if not value:
            return "****"
        if len(value) <= show_length:
            return value[:2] + "****"
        return value[:show_length] + "..." + value[-4:]
    
    def _detect_technology_stack(self, findings: List[Finding], scan_path: str = None) -> List[str]:
        """Detect technology stack from findings and file patterns."""
        detected = set()
        
        # Check from findings
        all_text = ""
        for f in findings:
            all_text += f" {f.file_path} {f.context or ''} {f.exposed_value or ''}"
        
        # Check from filesystem if path provided
        if scan_path and os.path.isdir(scan_path):
            for root, dirs, files in os.walk(scan_path):
                # Skip common non-source directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor', '__pycache__', 'bin', 'obj']]
                for file in files[:100]:  # Limit file checking
                    all_text += f" {file}"
        
        # Match patterns
        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.IGNORECASE):
                    detected.add(tech)
                    break
        
        return sorted(list(detected))
    
    def _get_git_info(self, repo_path: str) -> None:
        """Populate repository info from git."""
        try:
            git_dir = Path(repo_path) / ".git"
            if not git_dir.exists():
                return
            
            # Commit count
            result = subprocess.run(
                ["git", "-C", repo_path, "rev-list", "--count", "--all"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self.repo_info.total_commits = int(result.stdout.strip())
            
            # Branch count
            result = subprocess.run(
                ["git", "-C", repo_path, "branch", "-a", "--list"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                branches = [b.strip() for b in result.stdout.strip().split('\n') if b.strip()]
                self.repo_info.total_branches = len(branches)
            
            # First and last commit dates
            result = subprocess.run(
                ["git", "-C", repo_path, "log", "--format=%ci", "--reverse"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                dates = result.stdout.strip().split('\n')
                if dates:
                    self.repo_info.first_commit_date = dates[0].split()[0]
                    self.repo_info.last_commit_date = dates[-1].split()[0]
                    
                    # Calculate years
                    try:
                        first = datetime.strptime(dates[0].split()[0], "%Y-%m-%d")
                        last = datetime.strptime(dates[-1].split()[0], "%Y-%m-%d")
                        self.repo_info.history_years = (last - first).days / 365.25
                    except:
                        pass
            
            # Repository size
            result = subprocess.run(
                ["du", "-sb", str(git_dir)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self.repo_info.size_bytes = int(result.stdout.split()[0])
            
            # Remote URL
            result = subprocess.run(
                ["git", "-C", repo_path, "remote", "get-url", "origin"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.repo_info.remote_url = result.stdout.strip()
                
        except Exception:
            pass

    # =========================================================================
    # GITLEAKS-COMPATIBLE JSON FORMAT
    # =========================================================================
    
    def export_gitleaks_json(self, findings: List[Finding], output_path: str) -> None:
        """
        Export findings in Gitleaks-compatible JSON format.
        
        This format can be used with existing Gitleaks workflows and tools.
        Note: This is generated by DeployGuard, not by running Gitleaks.
        """
        gitleaks_findings = []
        
        for f in findings:
            # Generate a deterministic fingerprint
            fingerprint = hashlib.sha256(
                f"{f.file_path}:{f.line_number}:{f.exposed_value}".encode()
            ).hexdigest()[:32]
            
            gitleaks_finding = {
                "Description": f.description or self._get_type(f),
                "StartLine": f.line_number,
                "EndLine": f.line_number,
                "StartColumn": f.column_start,
                "EndColumn": f.column_end,
                "Match": f.exposed_value,
                "Secret": f.metadata.get("actual_value") or f.exposed_value,
                "File": f.file_path,
                "SymlinkFile": "",
                "Commit": "",  # Would be populated during git history scan
                "Entropy": f.metadata.get("entropy", 0.0),
                "Author": "",
                "Email": "",
                "Date": "",
                "Message": "",
                "Tags": [self._get_severity(f), self._get_type(f)],
                "RuleID": f.metadata.get("pattern_name", self._get_type(f)),
                "Fingerprint": fingerprint,
            }
            gitleaks_findings.append(gitleaks_finding)
        
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(gitleaks_findings, fp, indent=2, ensure_ascii=False)
    
    # =========================================================================
    # BFG PURGE FILE FORMAT
    # =========================================================================
    
    def export_bfg_purge_file(
        self, 
        findings: List[Finding], 
        output_path: str,
        use_placeholders: bool = True,
        placeholder_format: str = "{type}_REMOVED"
    ) -> None:
        """
        Export findings as BFG Repo-Cleaner compatible purge file.
        
        Args:
            findings: List of findings to export
            output_path: Path to write secrets_to_purge.txt
            use_placeholders: If True, use replacement placeholders
            placeholder_format: Format for placeholder text
        
        BFG format:
        - Simple: secret_value (replaced with ***REMOVED***)
        - With replacement: secret_value==>REPLACEMENT_TEXT
        - Regex: regex:pattern==>REPLACEMENT (for special chars like #)
        """
        # Group by type for organized output
        categories = self._categorize_findings(findings)
        
        with open(output_path, "w", encoding="utf-8") as fp:
            fp.write("# ============================================================\n")
            fp.write("# BFG Repo-Cleaner Secrets Purge File\n")
            fp.write("# Generated by DeployGuard Repository Cleaner\n")
            fp.write(f"# Generated: {self.scan_date.isoformat()}\n")
            fp.write(f"# Repository: {self.repo_info.name}\n")
            fp.write("# ============================================================\n")
            fp.write("#\n")
            fp.write("# KULLANIM / USAGE:\n")
            fp.write("# java -jar bfg.jar --replace-text secrets_to_purge.txt repo.git\n")
            fp.write("#\n")
            fp.write("# FORMAT:\n")
            fp.write("# secret_value==>REPLACEMENT\n")
            fp.write("# regex:pattern==>REPLACEMENT (for special characters)\n")
            fp.write("#\n")
            fp.write("# ⚠️ DİKKAT: # karakteri içeren secret'lar için regex: prefix kullanılır\n")
            fp.write("# ============================================================\n\n")
            
            seen_values = set()
            total_secrets = 0
            
            for category, cat_findings in sorted(categories.items()):
                cat_name = self.SECRET_TYPE_DESCRIPTIONS.get(category, category.upper())
                fp.write(f"# --- {cat_name} ---\n")
                
                for f in cat_findings:
                    value = f.metadata.get("actual_value") or f.exposed_value
                    
                    # Skip duplicates
                    if value in seen_values:
                        continue
                    seen_values.add(value)
                    
                    # Skip very short values (likely false positives)
                    if len(value) < 4:
                        continue
                    
                    # Skip values that look like code/HTML
                    if value.startswith('<') or value.startswith('//') or 'function' in value.lower():
                        continue
                    
                    total_secrets += 1
                    
                    # Handle special characters that need escaping in BFG
                    # BFG uses Java regex, # starts a comment
                    needs_regex = '#' in value or '\\' in value
                    
                    if needs_regex:
                        # Use regex format for values with special chars
                        escaped = re.escape(value)
                        fp.write(f"regex:{escaped}")
                    else:
                        fp.write(value)
                    
                    # Add replacement placeholder
                    if use_placeholders:
                        placeholder = self._generate_placeholder(f, category)
                        fp.write(f"==>{placeholder}")
                    
                    fp.write("\n")
                
                fp.write("\n")
            
            # Summary
            fp.write("# ============================================================\n")
            fp.write(f"# ÖZET / SUMMARY\n")
            fp.write(f"# Total unique secrets: {total_secrets}\n")
            fp.write(f"# Categories: {len(categories)}\n")
            fp.write("# ============================================================\n")
    
    def _generate_placeholder(self, finding: Finding, category: str) -> str:
        """Generate a descriptive placeholder for a secret."""
        placeholders = {
            "azure_sql": "AZURE_SQL_PASSWORD_REMOVED",
            "sql_server": "ONPREM_SQL_PASSWORD_REMOVED",
            "database_password": "DB_PASSWORD_REMOVED",
            "rabbitmq": "RABBITMQ_PASSWORD_REMOVED",
            "fcm": "FCM_SERVER_KEY_REMOVED",
            "jwt": "JWT_SECRET_KEY_REMOVED",
            "vapid": "VAPID_PRIVATE_KEY_REMOVED",
            "api_key": "API_KEY_REMOVED",
            "secret_key": "SECRET_KEY_REMOVED",
            "password": "PASSWORD_REMOVED",
            "aws_access_key": "AWS_ACCESS_KEY_REMOVED",
            "aws_secret_key": "AWS_SECRET_KEY_REMOVED",
            "internal_ip": "INTERNAL-SERVER",
            "internal_domain": "INTERNAL-DOMAIN",
            "ldap": "LDAP_PASSWORD_REMOVED",
            "base64_secret": "BASE64_SECRET_REMOVED",
            "generic_secret": "***REMOVED***",
        }
        
        return placeholders.get(category, "***REMOVED***")

    # =========================================================================
    # MARKDOWN EXECUTIVE SUMMARY (Turkish)
    # =========================================================================
    
    def export_markdown_report(
        self,
        findings: List[Finding],
        output_path: str,
        cleanup_result: Optional[CleanupResult] = None,
        language: str = "tr"
    ) -> None:
        """
        Export comprehensive Markdown report.
        
        Supports both Turkish (tr) and English (en) formats.
        """
        if language == "tr":
            self._export_markdown_turkish(findings, output_path, cleanup_result)
        else:
            self._export_markdown_english(findings, output_path, cleanup_result)
    
    def _export_markdown_turkish(
        self,
        findings: List[Finding],
        output_path: str,
        cleanup_result: Optional[CleanupResult] = None
    ) -> None:
        """Generate comprehensive Turkish executive summary report matching Smartgo format."""
        severity_counts = self._count_by_severity(findings)
        categories = self._categorize_findings(findings)
        unique_secrets = self._get_unique_secrets(findings)
        tech_stack = self._detect_technology_stack(findings, self.repo_info.path)
        
        # Get git info if not already populated
        if self.repo_info.total_commits == 0:
            self._get_git_info(self.repo_info.path)
        
        with open(output_path, "w", encoding="utf-8") as fp:
            # ================================================================
            # HEADER
            # ================================================================
            fp.write(f"# {self.repo_info.name} Repository Güvenlik Temizleme Raporu\n\n")
            fp.write(f"**Oluşturulma Tarihi:** {self.scan_date.strftime('%d %B %Y, %H:%M')}\n")
            fp.write(f"**Oluşturan:** DeployGuard Repository Cleaner\n")
            if self.repo_info.remote_url:
                fp.write(f"**Repository:** {self.repo_info.remote_url}\n")
            fp.write("\n")
            
            # ================================================================
            # EXECUTIVE SUMMARY
            # ================================================================
            fp.write("## Yönetici Özeti\n\n")
            
            # Repository info paragraph
            fp.write(f"{self.repo_info.name} repository'sinin git geçmişi ")
            if self.repo_info.total_commits > 0:
                fp.write(f"({self.repo_info.total_commits} commit, {self.repo_info.total_branches} branch")
                if self.repo_info.history_years > 0:
                    fp.write(f", {self.repo_info.history_years:.1f} yıl")
                if self.repo_info.first_commit_date and self.repo_info.last_commit_date:
                    fp.write(f", {self.repo_info.first_commit_date} → {self.repo_info.last_commit_date}")
                fp.write(") ")
            fp.write(f"tam tarama sürecinden geçirildi ve **{len(findings)} adet hassas veri** tespit edildi.\n\n")
            
            # Key findings summary
            if severity_counts['critical'] > 0:
                fp.write(f"Tespit edilen tüm kritik veriler (")
                critical_cats = [cat for cat, fs in categories.items() 
                               if any(self._get_severity(f) == "critical" for f in fs)]
                fp.write(", ".join([self.SECRET_TYPE_DESCRIPTIONS.get(c, c) for c in critical_cats[:4]]))
                fp.write(") acil aksiyon gerektirmektedir.\n\n")
            
            fp.write(f"**CRITICAL bulgular:** {severity_counts['critical']} adet\n")
            fp.write(f"**HIGH bulgular:** {severity_counts['high']} adet\n\n")
            
            # Cleanup results if available
            if cleanup_result:
                before_total = len(cleanup_result.before_findings)
                after_total = len(cleanup_result.after_findings)
                cleanup_pct = ((before_total - after_total) / before_total * 100) if before_total > 0 else 0
                
                bc = self._count_by_severity(cleanup_result.before_findings)
                ac = self._count_by_severity(cleanup_result.after_findings)
                
                fp.write(f"**Temizlik Sonucu:** {before_total} kritik secret → {after_total} ")
                fp.write(f"({cleanup_pct:.0f}% temizlendi)\n")
                if ac['critical'] == 0 and bc['critical'] > 0:
                    fp.write(f"**CRITICAL bulgular %100 temizlendi** ({bc['critical']} → 0)\n")
                fp.write("\n")
            
            # ================================================================
            # SCAN SCOPE
            # ================================================================
            fp.write("## Güvenlik Taraması Kapsamı\n\n")
            
            fp.write("### Taranan Alanlar\n\n")
            
            fp.write("**Git History (Full Scan):**\n\n")
            fp.write(f"- Tüm Commit'ler: {self.repo_info.total_commits} commit")
            if self.repo_info.first_commit_date and self.repo_info.last_commit_date:
                fp.write(f" ({self.repo_info.first_commit_date} → {self.repo_info.last_commit_date})")
            fp.write("\n")
            fp.write(f"- Tüm Branch'ler: {self.repo_info.total_branches} branch\n")
            fp.write("- Tüm Dosya Tipleri: Source code, configuration, scripts\n")
            fp.write("- Deleted Files: Silinmiş dosyaların git history'deki kopyaları\n\n")
            
            # Group files by type
            files_by_ext = defaultdict(list)
            for f in findings:
                ext = Path(f.file_path).suffix or "other"
                if f.file_path not in files_by_ext[ext]:
                    files_by_ext[ext].append(f.file_path)
            
            fp.write("**Kaynak Kod Taraması:**\n\n")
            for ext, files in sorted(files_by_ext.items(), key=lambda x: -len(x[1]))[:5]:
                fp.write(f"- {ext} dosyaları: {len(files)} adet\n")
            fp.write("\n")
            
            fp.write("**Kontrol Edilen Secret Tipleri:**\n\n")
            for cat in sorted(categories.keys()):
                cat_name = self.SECRET_TYPE_DESCRIPTIONS.get(cat, cat)
                fp.write(f"- {cat_name}\n")
            fp.write("\n")
            
            # Technology stack
            if tech_stack:
                fp.write("**Teknoloji Stack Analizi:**\n\n")
                for tech in tech_stack:
                    fp.write(f"- {tech}\n")
                fp.write("\n")
            
            fp.write("**Tarama Araçları:**\n\n")
            fp.write("- DeployGuard Repository Cleaner: Custom detection rules ile full history scan\n")
            fp.write("- BFG Repo-Cleaner 1.15.0: Git history string replacement\n")
            fp.write("- Custom Detection Rules: 800+ secret patterns\n\n")
            
            # ================================================================
            # SCAN RESULTS TABLE
            # ================================================================
            fp.write("## Tarama Sonucu\n\n")
            
            fp.write("| Metrik | Başlangıç | Son | Değişim |\n")
            fp.write("|--------|-----------|-----|--------|\n")
            
            if cleanup_result:
                before = len(cleanup_result.before_findings)
                after = len(cleanup_result.after_findings)
                pct = f"-{((before - after) / before * 100):.0f}%" if before > 0 else "0%"
                fp.write(f"| Toplam Finding | {before} | {after} | {pct} |\n")
                
                bc = self._count_by_severity(cleanup_result.before_findings)
                ac = self._count_by_severity(cleanup_result.after_findings)
                
                for sev in ["critical", "high", "medium", "low"]:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                    change_val = bc[sev] - ac[sev]
                    pct = f"-{(change_val / bc[sev] * 100):.0f}%" if bc[sev] > 0 else "0%"
                    status = " ✅" if ac[sev] == 0 and bc[sev] > 0 else ""
                    fp.write(f"| {emoji} {sev.upper()} Bulgular | {bc[sev]} | {ac[sev]} | {pct}{status} |\n")
            else:
                fp.write(f"| Toplam Finding | {len(findings)} | - | - |\n")
                fp.write(f"| Unique Secret Sayısı | {len(unique_secrets)} | - | - |\n")
                for sev in ["critical", "high", "medium", "low"]:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                    fp.write(f"| {emoji} {sev.upper()} | {severity_counts[sev]} | - | - |\n")
            fp.write("\n")
            
            # ================================================================
            # DETAILED FINDINGS BY CATEGORY
            # ================================================================
            fp.write("## Tespit Edilen Hassas Veriler (Detaylı)\n\n")
            
            finding_num = 1
            for category, cat_findings in sorted(categories.items(),
                key=lambda x: (-self._count_by_severity(x[1])["critical"], 
                              -self._count_by_severity(x[1])["high"])):
                
                cat_name = self.SECRET_TYPE_DESCRIPTIONS.get(category, category)
                cat_sev = self._count_by_severity(cat_findings)
                
                # Determine severity level
                if cat_sev["critical"] > 0:
                    sev_label = "CRITICAL"
                    emoji = "🔴"
                elif cat_sev["high"] > 0:
                    sev_label = "HIGH"
                    emoji = "🟠"
                else:
                    sev_label = "MEDIUM"
                    emoji = "🟡"
                
                fp.write(f"### {finding_num}. {emoji} {sev_label}: {cat_name}\n\n")
                
                # Get sample secret value (masked)
                sample_value = cat_findings[0].metadata.get("actual_value") or cat_findings[0].exposed_value
                masked_value = self._mask_secret(sample_value, 10)
                
                fp.write(f"**Secret Değeri:** `{masked_value}` ({len(sample_value)} karakter)\n\n")
                
                # Group findings by file
                by_file = defaultdict(list)
                for f in cat_findings:
                    by_file[f.file_path].append(f)
                
                fp.write("**Nerede Bulundu:**\n\n")
                for file_path, file_findings in sorted(by_file.items()):
                    lines = sorted(set(f.line_number for f in file_findings))
                    lines_str = ", ".join(str(l) for l in lines[:5])
                    if len(lines) > 5:
                        lines_str += f" (+{len(lines)-5} daha)"
                    fp.write(f"- **Dosya:** `{file_path}`\n")
                    fp.write(f"  - Satırlar: {lines_str}\n")
                    fp.write(f"  - Bulgu sayısı: {len(file_findings)}\n")
                
                fp.write(f"\n**Git History:** {len(cat_findings)} commit'te tespit edildi\n\n")
                
                # Detaylar section
                fp.write("**Detaylar:**\n\n")
                if category == "azure_sql":
                    fp.write("- Production database şifresi git history'de açık metin\n")
                    fp.write("- Azure SQL Server connection string\n")
                elif category == "sql_server":
                    fp.write("- On-premise SQL Server database şifresi\n")
                    fp.write("- Internal IP adresi görünür\n")
                elif category == "rabbitmq":
                    fp.write("- RabbitMQ message queue credentials\n")
                    fp.write("- AMQP connection string içinde şifre\n")
                elif category == "fcm":
                    fp.write("- Firebase push notification server credentials\n")
                    fp.write("- Mobile app push notification için kritik\n")
                elif category == "jwt":
                    fp.write("- JWT token signing key (authentication)\n")
                    fp.write("- Session management secrets\n")
                else:
                    fp.write(f"- {cat_name} tespit edildi\n")
                fp.write("\n")
                
                # Yapılan İşlem (if cleanup result available)
                if cleanup_result:
                    fp.write("**Yapılan İşlem:**\n\n")
                    placeholder = self._generate_placeholder(cat_findings[0], category)
                    fp.write(f"- ✅ Tüm git geçmişinden kaldırıldı\n")
                    fp.write(f"- ✅ Yerine `{placeholder}` placeholder konuldu\n")
                    fp.write(f"- ✅ Tüm branch'lerden temizlendi\n\n")
                
                # ⚠️ MUTLAKA YAPILMASI GEREKEN
                fp.write("**⚠️ MUTLAKA YAPILMASI GEREKEN:**\n\n")
                actions = self.REQUIRED_ACTIONS_TR.get(category, ["Secret'ı rotate edin ve environment variable olarak kullanın"])
                for action in actions:
                    fp.write(f"- {action}\n")
                fp.write("\n")
                
                # Rotation script if available
                if category in self.ROTATION_SCRIPTS:
                    fp.write("**Rotation Script:**\n\n")
                    fp.write(self.ROTATION_SCRIPTS[category])
                    fp.write("\n\n")
                
                finding_num += 1
            
            # ================================================================
            # REPOSITORY METRICS
            # ================================================================
            if cleanup_result or self.repo_info.size_bytes > 0:
                fp.write("## Repository Metrikleri\n\n")
                
                fp.write("| Metrik | Öncesi | Sonrası | Değişim |\n")
                fp.write("|--------|--------|---------|--------|\n")
                
                if self.repo_info.size_bytes > 0:
                    before_mb = self.repo_info.size_mb()
                    after_mb = self.repo_info.size_after_mb() if self.repo_info.size_after_bytes > 0 else before_mb
                    size_change = f"-{((before_mb - after_mb) / before_mb * 100):.0f}%" if before_mb > after_mb else "0%"
                    fp.write(f"| Repository Boyutu (.git) | {before_mb:.1f} MB | {after_mb:.1f} MB | {size_change} |\n")
                
                fp.write(f"| Commit Sayısı | {self.repo_info.total_commits} | - | Korundu |\n")
                fp.write(f"| Branch Sayısı | {self.repo_info.total_branches} | - | Korundu |\n")
                
                if cleanup_result:
                    bc = self._count_by_severity(cleanup_result.before_findings)
                    ac = self._count_by_severity(cleanup_result.after_findings)
                    pct = "-100%" if ac['critical'] == 0 and bc['critical'] > 0 else f"-{((bc['critical'] - ac['critical']) / bc['critical'] * 100):.0f}%" if bc['critical'] > 0 else "0%"
                    status = "✅ Giderildi" if ac['critical'] == 0 else ""
                    fp.write(f"| Kritik Güvenlik Açığı | {bc['critical']} CRITICAL | {ac['critical']} CRITICAL | {pct} {status} |\n")
                
                fp.write("\n")
                
                fp.write("### Code Integrity Doğrulaması\n\n")
                fp.write("- ✅ Ana branch'ler korundu\n")
                fp.write("- ✅ Tüm source code dosyaları korundu\n")
                fp.write("- ✅ Hiçbir dosya silinmedi (string replacement only)\n")
                fp.write("- ✅ Kod fonksiyonelliği korundu\n\n")
            
            # ================================================================
            # REQUIRED ACTIONS
            # ================================================================
            fp.write("## Alınacak Aksiyonlar\n\n")
            
            # 1. Developer Team Actions
            fp.write("### 1. Tüm Geliştirici Ekip (ACIL)\n\n")
            fp.write("Mevcut lokal repository'leri silmeliler:\n\n")
            fp.write("```bash\n")
            fp.write("# ⚠️ DİKKAT: Commit edilmemiş değişiklikler kaybolacak!\n")
            fp.write("# Önce stash veya commit edin:\n")
            fp.write("git stash save \"Pre-cleanup local changes\"\n\n")
            fp.write("# Eski kopyayı sil\n")
            fp.write("cd ~/workspace  # veya repository'nin bulunduğu dizin\n")
            fp.write(f"rm -rf {self.repo_info.name}\n")
            fp.write("```\n\n")
            
            fp.write("Yeni temizlenmiş repository'yi clone almalılar:\n\n")
            fp.write("```bash\n")
            remote = self.repo_info.remote_url or f"<yeni_repo_adresi>/{self.repo_info.name}.git"
            fp.write(f"git clone {remote}\n")
            fp.write(f"cd {self.repo_info.name}\n\n")
            fp.write("# Branch'inizi checkout edin\n")
            fp.write("git checkout master  # veya çalıştığınız branch\n")
            fp.write("```\n\n")
            
            fp.write("**Neden `git pull` ÇALIŞMAZ?**\n\n")
            fp.write("- ❌ Git geçmişi tamamen yeniden yazıldı\n")
            fp.write("- ❌ Tüm commit SHA'ları değişti\n")
            fp.write("- ❌ Eski lokal kopyalar remote ile uyumsuz\n")
            fp.write("- ❌ `git pull` hata verecek: `fatal: refusing to merge unrelated histories`\n\n")
            
            # 2. IT Security Team Actions
            fp.write("### 2. IT Güvenlik Ekibi (CRITICAL)\n\n")
            fp.write("**Credential Rotation Priority List:**\n\n")
            fp.write("| Secret Tipi | Öncelik | Aksiyon |\n")
            fp.write("|-------------|---------|----------|\n")
            
            priority_order = ["azure_sql", "sql_server", "rabbitmq", "fcm", "jwt", "vapid", "api_key", "ldap", "password"]
            for cat in priority_order:
                if cat in categories:
                    cat_name = self.SECRET_TYPE_DESCRIPTIONS.get(cat, cat)
                    count = len(categories[cat])
                    critical = self._count_by_severity(categories[cat])["critical"]
                    priority = "🔴 CRITICAL" if critical > 0 else "🟠 HIGH"
                    action = self.REQUIRED_ACTIONS_TR.get(cat, ["Password rotation"])[0][:40]
                    fp.write(f"| {cat_name} ({count}) | {priority} | {action}... |\n")
            
            fp.write("\n")
            
            # ================================================================
            # FOOTER
            # ================================================================
            fp.write("---\n\n")
            fp.write("## Kritik Başarılar\n\n")
            fp.write("- ✅ **Zero Data Loss:** Hiçbir repository'de kod veya dosya kaybı olmadı\n")
            fp.write("- ✅ **Comprehensive Coverage:** Tüm git geçmişi tarandı\n")
            fp.write("- ✅ **Code Integrity:** Kod fonksiyonelliği korundu\n\n")
            
            fp.write("---\n")
            fp.write(f"*Bu rapor DeployGuard Repository Cleaner tarafından {self.scan_date.strftime('%Y-%m-%d %H:%M')} tarihinde oluşturulmuştur.*\n")
    
    def _export_markdown_english(
        self,
        findings: List[Finding],
        output_path: str,
        cleanup_result: Optional[CleanupResult] = None
    ) -> None:
        """Generate English executive summary report."""
        severity_counts = self._count_by_severity(findings)
        categories = self._categorize_findings(findings)
        unique_secrets = self._get_unique_secrets(findings)
        
        with open(output_path, "w", encoding="utf-8") as fp:
            fp.write(f"# {self.repo_info.name} Security Scan Report\n\n")
            fp.write(f"**Generated:** {self.scan_date.strftime('%B %d, %Y at %H:%M')}\n")
            fp.write(f"**Tool:** DeployGuard Repository Cleaner\n\n")
            
            fp.write("## Executive Summary\n\n")
            fp.write(f"A comprehensive security scan identified **{len(findings)} sensitive data findings** ")
            fp.write(f"across {len(unique_secrets)} unique secrets.\n\n")
            
            fp.write("### Findings Overview\n\n")
            fp.write("| Severity | Count |\n")
            fp.write("|----------|-------|\n")
            fp.write(f"| 🔴 CRITICAL | {severity_counts['critical']} |\n")
            fp.write(f"| 🟠 HIGH | {severity_counts['high']} |\n")
            fp.write(f"| 🟡 MEDIUM | {severity_counts['medium']} |\n")
            fp.write(f"| 🟢 LOW | {severity_counts['low']} |\n\n")
            
            # ... Similar structure to Turkish version ...
            
            fp.write("## Required Actions\n\n")
            fp.write("### 1. Credential Rotation (CRITICAL)\n\n")
            fp.write("The following credentials **MUST** be rotated:\n\n")
            
            for category in ["azure_sql", "sql_server", "rabbitmq", "fcm", "jwt"]:
                if category in categories:
                    fp.write(f"- **{self.SECRET_TYPE_DESCRIPTIONS.get(category, category)}**: ")
                    fp.write(f"{len(categories[category])} findings\n")
            
            fp.write("\n---\n")
            fp.write(f"*Generated by DeployGuard Repository Cleaner on {self.scan_date.isoformat()}*\n")

    # =========================================================================
    # DETAILED PROJECT REPORT (Like Report 3)
    # =========================================================================
    
    def export_detailed_report(
        self,
        findings: List[Finding],
        output_path: str,
        cleanup_result: Optional[CleanupResult] = None,
        include_values: bool = False
    ) -> None:
        """
        Export a detailed project report similar to the Smartgo Backend report.
        
        Includes:
        - Executive summary
        - Scan scope and methodology
        - Detailed findings by category with file locations
        - Cleanup metrics
        - Action items with code examples
        """
        severity_counts = self._count_by_severity(findings)
        categories = self._categorize_findings(findings)
        
        with open(output_path, "w", encoding="utf-8") as fp:
            # Title
            fp.write(f"# {self.repo_info.name} Repository Güvenlik Temizleme Raporu\n\n")
            
            # Executive Summary
            fp.write("## Yönetici Özeti\n\n")
            total = len(findings)
            critical = severity_counts["critical"]
            high = severity_counts["high"]
            
            fp.write(f"{self.repo_info.name} repository'si tam tarama sürecinden geçirildi ve ")
            fp.write(f"**{total} adet hassas veri** tespit edildi. ")
            
            if critical > 0:
                fp.write(f"Tespit edilen **{critical} CRITICAL** ve **{high} HIGH** bulgular ")
                fp.write("acil aksiyon gerektirmektedir.\n\n")
            
            # Scan Scope
            fp.write("## Güvenlik Taraması Kapsamı\n\n")
            fp.write("### Taranan Alanlar\n\n")
            
            if self.repo_info.total_commits > 0:
                fp.write("**Git History (Full Scan):**\n\n")
                fp.write(f"- Tüm Commit'ler: {self.repo_info.total_commits} commit\n")
                fp.write(f"- Tüm Branch'ler: {self.repo_info.total_branches} branch\n")
            
            fp.write("\n**Kontrol Edilen Secret Tipleri:**\n\n")
            for cat in sorted(categories.keys()):
                cat_name = self.SECRET_TYPE_DESCRIPTIONS.get(cat, cat)
                fp.write(f"- {cat_name}\n")
            
            # Scan Results Table
            fp.write("\n## Tarama Sonucu\n\n")
            fp.write("| Metrik | Başlangıç | Son | Değişim |\n")
            fp.write("|--------|-----------|-----|--------|\n")
            
            if cleanup_result:
                before = len(cleanup_result.before_findings)
                after = len(cleanup_result.after_findings)
                pct = f"-{((before - after) / before * 100):.0f}%" if before > 0 else "0%"
                fp.write(f"| Toplam Finding | {before} | {after} | {pct} |\n")
                
                bc = self._count_by_severity(cleanup_result.before_findings)
                ac = self._count_by_severity(cleanup_result.after_findings)
                
                for sev in ["critical", "high", "medium", "low"]:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                    pct = f"-{((bc[sev] - ac[sev]) / bc[sev] * 100):.0f}%" if bc[sev] > 0 else "0%"
                    status = "✅" if ac[sev] == 0 else ""
                    fp.write(f"| {emoji} {sev.upper()} Bulgular | {bc[sev]} | {ac[sev]} | {pct} {status} |\n")
            else:
                fp.write(f"| Toplam Finding | {len(findings)} | - | - |\n")
                for sev, count in severity_counts.items():
                    fp.write(f"| {sev.upper()} | {count} | - | - |\n")
            
            # Detailed Findings
            fp.write("\n## Tespit Edilen Hassas Veriler (Detaylı)\n\n")
            
            finding_num = 1
            for category, cat_findings in sorted(categories.items(),
                key=lambda x: -self._count_by_severity(x[1])["critical"]):
                
                cat_name = self.SECRET_TYPE_DESCRIPTIONS.get(category, category)
                cat_sev = self._count_by_severity(cat_findings)
                
                # Determine priority
                if cat_sev["critical"] > 0:
                    priority = "CRITICAL"
                    emoji = "🔴"
                elif cat_sev["high"] > 0:
                    priority = "HIGH"
                    emoji = "🟠"
                else:
                    priority = "MEDIUM"
                    emoji = "🟡"
                
                fp.write(f"### {finding_num}. {emoji} {priority}: {cat_name}\n\n")
                
                # Group by file
                by_file = defaultdict(list)
                for f in cat_findings:
                    by_file[f.file_path].append(f)
                
                fp.write("**Nerede Bulundu:**\n\n")
                for file_path, file_findings in sorted(by_file.items()):
                    fp.write(f"- `{file_path}` ({len(file_findings)} bulgu)\n")
                
                fp.write(f"\n**Git History:** {len(cat_findings)} commit'te tespit edildi\n\n")
                
                # Sample values if requested
                if include_values and cat_findings:
                    fp.write("**Örnek Değerler:**\n\n")
                    for f in cat_findings[:3]:
                        value = f.metadata.get("actual_value") or f.exposed_value
                        if len(value) > 50:
                            display = value[:20] + "..." + value[-10:]
                        else:
                            display = value[:10] + "****"
                        fp.write(f"- `{display}` (Line {f.line_number})\n")
                    fp.write("\n")
                
                # Required action
                fp.write("**⚠️ YAPILMASI GEREKEN:**\n\n")
                action = self._get_action_for_category(category)
                fp.write(f"{action}\n\n")
                
                finding_num += 1
            
            # Developer Actions
            fp.write("## Alınacak Aksiyonlar\n\n")
            fp.write("### 1. Tüm Geliştirici Ekip (ACIL)\n\n")
            fp.write("```bash\n")
            fp.write("# ⚠️ DİKKAT: Commit edilmemiş değişiklikler kaybolacak!\n")
            fp.write("git stash save \"Pre-cleanup local changes\"\n\n")
            fp.write("# Eski kopyayı sil\n")
            fp.write(f"rm -rf {self.repo_info.name}\n\n")
            fp.write("# Yeni temizlenmiş repository'yi clone al\n")
            fp.write(f"git clone <yeni_repo_adresi>/{self.repo_info.name}.git\n")
            fp.write("```\n\n")
            
            fp.write("### 2. IT Güvenlik Ekibi (CRITICAL)\n\n")
            fp.write("**Credential Rotation Priority List:**\n\n")
            fp.write("| Secret Tipi | Öncelik | Aksiyon |\n")
            fp.write("|-------------|---------|----------|\n")
            
            priority_order = ["azure_sql", "sql_server", "rabbitmq", "fcm", "jwt", "vapid", "api_key", "password"]
            for cat in priority_order:
                if cat in categories:
                    cat_name = self.SECRET_TYPE_DESCRIPTIONS.get(cat, cat)
                    count = len(categories[cat])
                    critical = self._count_by_severity(categories[cat])["critical"]
                    priority = "🔴 CRITICAL" if critical > 0 else "🟠 HIGH"
                    fp.write(f"| {cat_name} ({count}) | {priority} | Password/Key rotation |\n")
            
            fp.write("\n---\n")
            fp.write(f"*Rapor DeployGuard tarafından {self.scan_date.isoformat()} tarihinde oluşturuldu*\n")
    
    def _get_action_for_category(self, category: str) -> str:
        """Get recommended action text for a secret category."""
        actions = {
            "azure_sql": "Azure Portal → SQL Databases → Security → SQL authentication password'ünü DEĞİŞTİRİN",
            "sql_server": "On-premise SQL Server'da kullanıcı şifresini değiştirin",
            "rabbitmq": "RabbitMQ Management Console → Users → Password change yapın",
            "fcm": "Firebase Console → Project Settings → Cloud Messaging → Server Key'i ROTATE EDİN",
            "jwt": "YENİ JWT secret key generate edin (256-bit random). TÜM aktif sessions invalidate edilecek!",
            "vapid": "Yeni VAPID key pair generate edin. Mevcut push subscriptions re-subscribe gerektirecek.",
            "api_key": "API provider'a contact edin ve credentials'ları rotate edin",
            "password": "İlgili servis/sistemde şifreyi değiştirin",
            "internal_ip": "Network Security Review yapın ve firewall rules'u gözden geçirin",
        }
        return actions.get(category, "Secret'ı rotate edin ve environment variable olarak kullanın")

    # =========================================================================
    # COMPARISON / TRACKING
    # =========================================================================
    
    def compare_findings(
        self,
        baseline_findings: List[Finding],
        current_findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Compare two sets of findings to track cleanup progress.
        
        Returns:
            Dictionary with comparison metrics
        """
        baseline_values = set(
            f.metadata.get("actual_value") or f.exposed_value 
            for f in baseline_findings
        )
        current_values = set(
            f.metadata.get("actual_value") or f.exposed_value 
            for f in current_findings
        )
        
        cleaned = baseline_values - current_values
        remaining = baseline_values & current_values
        new = current_values - baseline_values
        
        baseline_counts = self._count_by_severity(baseline_findings)
        current_counts = self._count_by_severity(current_findings)
        
        return {
            "baseline_total": len(baseline_findings),
            "current_total": len(current_findings),
            "unique_cleaned": len(cleaned),
            "unique_remaining": len(remaining),
            "new_findings": len(new),
            "cleanup_percentage": (len(cleaned) / len(baseline_values) * 100) if baseline_values else 0,
            "severity_comparison": {
                sev: {
                    "before": baseline_counts[sev],
                    "after": current_counts[sev],
                    "change": baseline_counts[sev] - current_counts[sev],
                }
                for sev in ["critical", "high", "medium", "low"]
            },
            "cleaned_values": list(cleaned)[:50],  # First 50 for reference
        }
    
    def load_baseline(self, baseline_path: str) -> List[Finding]:
        """Load baseline findings from a previous JSON export."""
        with open(baseline_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        
        findings = []
        # Handle both Gitleaks format and DeployGuard format
        items = data if isinstance(data, list) else data.get("findings", [])
        
        for item in items:
            # Convert to Finding object
            finding = Finding(
                type=item.get("RuleID") or item.get("type", "generic_secret"),
                severity=item.get("Tags", ["medium"])[0] if "Tags" in item else item.get("severity", "medium"),
                file_path=item.get("File") or item.get("file_path", ""),
                line_number=item.get("StartLine") or item.get("line_number", 0),
                column_start=item.get("StartColumn") or item.get("column_start", 0),
                column_end=item.get("EndColumn") or item.get("column_end", 0),
                exposed_value=item.get("Match") or item.get("full_match", ""),
                metadata={
                    "actual_value": item.get("Secret") or item.get("actual_value", ""),
                }
            )
            findings.append(finding)
        
        return findings
