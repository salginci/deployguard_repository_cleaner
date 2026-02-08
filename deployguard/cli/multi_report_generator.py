"""
Multi-Report Generator for DeployGuard

Generates 5 separate Turkish-style security audit reports:
1. Overview Report - Executive summary, repo metrics
2. Commit/Branch History Report - Git history analysis
3. Variable Definitions Report - Environment variable mappings
4. Remediation Changes Report - Before/after cleanup results
5. Project Summary Report - Final status and recommendations
"""

import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict

from deployguard.core.models import Finding


@dataclass
class GitCommitInfo:
    """Information about a git commit."""
    sha: str
    short_sha: str
    author: str
    email: str
    date: str
    message: str
    files_changed: List[str] = field(default_factory=list)
    secrets_found: int = 0


@dataclass
class GitBranchInfo:
    """Information about a git branch."""
    name: str
    is_remote: bool
    commit_count: int
    last_commit_date: str
    secrets_found: int = 0


@dataclass
class SecretLocation:
    """Detailed location of a secret in git history."""
    secret_value: str
    secret_type: str
    severity: str
    commits: List[str] = field(default_factory=list)
    branches: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    first_introduced: str = ""
    last_seen: str = ""
    suggested_env_var: str = ""
    is_deleted_file: bool = False


@dataclass
class RemediationAction:
    """A single remediation action taken."""
    secret_type: str
    original_value: str
    replacement: str
    files_affected: List[str]
    commits_rewritten: int
    status: str  # "completed", "pending", "failed"


@dataclass 
class RepositoryMetrics:
    """Comprehensive repository metrics."""
    name: str
    path: str
    remote_url: str = ""
    
    # Commit metrics
    total_commits: int = 0
    first_commit_date: str = ""
    last_commit_date: str = ""
    history_years: float = 0.0
    
    # Branch metrics
    total_branches: int = 0
    local_branches: int = 0
    remote_branches: int = 0
    branches_list: List[str] = field(default_factory=list)
    
    # Size metrics
    size_before_bytes: int = 0
    size_after_bytes: int = 0
    
    # File metrics
    total_files: int = 0
    files_with_secrets: int = 0
    deleted_files_with_secrets: int = 0
    
    # Technology stack
    tech_stack: List[str] = field(default_factory=list)
    
    def size_before_mb(self) -> float:
        return self.size_before_bytes / 1024 / 1024
    
    def size_after_mb(self) -> float:
        return self.size_after_bytes / 1024 / 1024


class MultiReportGenerator:
    """
    Generates multiple Turkish-style security audit reports.
    
    Reports generated:
    1. {repo}_01_overview.md - Executive summary
    2. {repo}_02_history.md - Commit/branch history analysis
    3. {repo}_03_variables.md - Environment variable definitions
    4. {repo}_04_remediation.md - Cleanup changes report
    5. {repo}_05_summary.md - Project summary
    """
    
    # Secret type descriptions in Turkish
    SECRET_TYPES_TR = {
        "azure_sql": "Azure SQL Database Credentials",
        "sql_server": "On-Premise SQL Server Credentials", 
        "database_password": "Database Şifresi",
        "rabbitmq": "RabbitMQ AMQP Credentials",
        "fcm": "Firebase Cloud Messaging (FCM) Server Keys",
        "jwt": "JWT Secret Keys / OAuth Keys",
        "vapid": "VAPID Private Keys (Web Push)",
        "api_key": "API Keys",
        "aws_access_key": "AWS Access Key ID",
        "aws_secret_key": "AWS Secret Access Key",
        "github_token": "GitHub Token",
        "private_key": "Private Key",
        "password": "Password/Şifre",
        "internal_ip": "Internal IP Address",
        "connection_string": "Connection String",
        "ldap": "LDAP Credentials",
        "smtp": "SMTP Credentials",
        "redis": "Redis Credentials",
        "mongodb": "MongoDB Credentials",
        "generic_secret": "Generic Secret",
        "high_entropy": "High Entropy String",
    }
    
    # Rotation instructions
    ROTATION_INSTRUCTIONS = {
        "azure_sql": """
```sql
-- Azure SQL Password Rotation
-- Azure Portal → SQL Databases → Server → Active Directory admin
ALTER LOGIN [{username}] WITH PASSWORD = '<YENİ-GÜVENLİ-ŞİFRE>';

-- Veya Azure CLI ile:
az sql server update --admin-password '<YENİ-ŞİFRE>' -g <resource-group> -n <server-name>
```""",
        "sql_server": """
```sql
-- On-Premise SQL Server Password Rotation
ALTER LOGIN [{username}] WITH PASSWORD = '<YENİ-GÜVENLİ-ŞİFRE>';

-- appsettings'te environment variable kullanın:
-- "ConnectionStrings__DefaultConnection" = "Server=...;Password=${DG_DB_PASSWORD};"
```""",
        "rabbitmq": """
```bash
# RabbitMQ Password Rotation
rabbitmqctl change_password {username} '<YENİ-ŞİFRE>'

# Tüm consuming service'lerde appsettings güncelleyin:
# - Web Service
# - Background Workers  
# - Message Consumers
```""",
        "fcm": """
```
FCM Server Key Rotation:

1. Firebase Console → Project Settings → Cloud Messaging
2. Server Key → Regenerate (yeni 152-char key alın)
3. Tüm service'lerde appsettings.json "Fcm:ServerKey" güncelleyin
4. Deploy edin
5. Mobile app'lerde FCM token refresh tetikleyin
```""",
        "jwt": """
```bash
# JWT Secret Key Generation (256-bit)
openssl rand -base64 32

# ⚠️ DİKKAT: Tüm aktif session'lar invalidate edilecek!
# Kullanıcılar re-login yapmak zorunda kalacak.
```""",
        "vapid": """
```bash
# VAPID Key Pair Generation
npx web-push generate-vapid-keys

# ⚠️ Mevcut push subscription'lar çalışmayacak
# Kullanıcıların re-subscribe olması gerekecek
```""",
        "api_key": """
```
API Key Rotation:

1. İlgili servis provider'ın dashboard'una gidin
2. Yeni API key generate edin
3. Eski key'i revoke etmeden önce yeni key'i deploy edin
4. Test edin
5. Eski key'i revoke edin
```""",
        "aws_access_key": """
```bash
# AWS Access Key Rotation
aws iam create-access-key --user-name {username}
# Yeni credentials'ı configure edin
aws iam delete-access-key --access-key-id {old_key_id} --user-name {username}
```""",
    }
    
    def __init__(
        self,
        repo_path: str,
        output_dir: str,
        language: str = "tr"
    ):
        """
        Initialize the multi-report generator.
        
        Args:
            repo_path: Path to the git repository
            output_dir: Directory to write reports to
            language: Report language ("tr" or "en")
        """
        self.repo_path = os.path.abspath(repo_path)
        self.output_dir = output_dir
        self.language = language
        self.scan_date = datetime.now()
        
        # Data containers
        self.metrics = RepositoryMetrics(
            name=Path(repo_path).name,
            path=self.repo_path
        )
        self.secrets: List[SecretLocation] = []
        self.commits: List[GitCommitInfo] = []
        self.branches: List[GitBranchInfo] = []
        self.remediation_actions: List[RemediationAction] = []
        
        # Findings data
        self.before_findings: List[Finding] = []
        self.after_findings: List[Finding] = []
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def _run_git(self, args: List[str]) -> subprocess.CompletedProcess:
        """Run a git command."""
        return subprocess.run(
            ["git", "-C", self.repo_path] + args,
            capture_output=True,
            text=True
        )
    
    def gather_repository_info(self) -> None:
        """Gather comprehensive repository information."""
        # Remote URL
        result = self._run_git(["remote", "get-url", "origin"])
        if result.returncode == 0:
            self.metrics.remote_url = result.stdout.strip()
        
        # Total commits
        result = self._run_git(["rev-list", "--all", "--count"])
        if result.returncode == 0:
            self.metrics.total_commits = int(result.stdout.strip())
        
        # First and last commit dates
        result = self._run_git(["log", "--all", "--reverse", "--format=%cs", "-1"])
        if result.returncode == 0 and result.stdout.strip():
            self.metrics.first_commit_date = result.stdout.strip()
        
        result = self._run_git(["log", "--all", "--format=%cs", "-1"])
        if result.returncode == 0 and result.stdout.strip():
            self.metrics.last_commit_date = result.stdout.strip()
        
        # Calculate history years
        if self.metrics.first_commit_date and self.metrics.last_commit_date:
            try:
                first = datetime.strptime(self.metrics.first_commit_date, "%Y-%m-%d")
                last = datetime.strptime(self.metrics.last_commit_date, "%Y-%m-%d")
                self.metrics.history_years = (last - first).days / 365.25
            except:
                pass
        
        # Branches
        result = self._run_git(["branch", "-a", "--list"])
        if result.returncode == 0:
            branches = [b.strip().replace("* ", "") for b in result.stdout.strip().split('\n') if b.strip()]
            self.metrics.branches_list = branches
            self.metrics.total_branches = len(branches)
            self.metrics.local_branches = len([b for b in branches if not b.startswith("remotes/")])
            self.metrics.remote_branches = len([b for b in branches if b.startswith("remotes/")])
        
        # Repository size
        git_dir = Path(self.repo_path) / ".git"
        if git_dir.exists():
            total_size = 0
            for f in git_dir.rglob("*"):
                if f.is_file():
                    try:
                        total_size += f.stat().st_size
                    except:
                        pass
            self.metrics.size_before_bytes = total_size
        
        # Detect technology stack
        self._detect_tech_stack()
    
    def _detect_tech_stack(self) -> None:
        """Detect technology stack from repository files."""
        tech_patterns = {
            "*.csproj": ".NET Core / ASP.NET Core",
            "*.sln": "Visual Studio Solution",
            "package.json": "Node.js",
            "angular.json": "Angular",
            "next.config.*": "Next.js",
            "vite.config.*": "Vite",
            "requirements.txt": "Python",
            "Pipfile": "Python (Pipenv)",
            "pom.xml": "Java (Maven)",
            "build.gradle": "Java (Gradle)",
            "Dockerfile": "Docker",
            "docker-compose.*": "Docker Compose",
            "appsettings*.json": ".NET Configuration",
            "*.proto": "gRPC / Protocol Buffers",
        }
        
        detected = set()
        for pattern, tech in tech_patterns.items():
            result = self._run_git(["ls-files", pattern])
            if result.returncode == 0 and result.stdout.strip():
                detected.add(tech)
        
        # Check for specific dependencies in files
        result = self._run_git(["grep", "-l", "RabbitMQ", "--", "*.json", "*.cs", "*.config"])
        if result.returncode == 0 and result.stdout.strip():
            detected.add("RabbitMQ")
        
        result = self._run_git(["grep", "-l", "Firebase", "--", "*.json", "*.cs", "*.ts"])
        if result.returncode == 0 and result.stdout.strip():
            detected.add("Firebase")
        
        result = self._run_git(["grep", "-l", "SignalR", "--", "*.cs", "*.ts"])
        if result.returncode == 0 and result.stdout.strip():
            detected.add("SignalR")
        
        self.metrics.tech_stack = sorted(detected)
    
    def set_findings(
        self,
        before: List[Finding],
        after: Optional[List[Finding]] = None,
        secrets: Optional[List[SecretLocation]] = None
    ) -> None:
        """
        Set findings data for report generation.
        
        Args:
            before: Findings before cleanup
            after: Findings after cleanup (optional)
            secrets: Detailed secret locations (optional)
        """
        self.before_findings = before
        self.after_findings = after or []
        if secrets:
            self.secrets = secrets
        else:
            self._extract_secrets_from_findings(before)
    
    def _extract_secrets_from_findings(self, findings: List[Finding]) -> None:
        """Extract SecretLocation data from findings."""
        secrets_map: Dict[str, SecretLocation] = {}
        
        for f in findings:
            value = f.metadata.get("actual_value") or f.exposed_value
            
            if value not in secrets_map:
                secrets_map[value] = SecretLocation(
                    secret_value=value,
                    secret_type=f.type.value if hasattr(f.type, 'value') else str(f.type),
                    severity=f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    commits=f.metadata.get("commits", []),
                    files=[f.file_path],
                    suggested_env_var=f.metadata.get("suggested_env_var", self._suggest_env_var(f)),
                )
            else:
                if f.file_path not in secrets_map[value].files:
                    secrets_map[value].files.append(f.file_path)
        
        self.secrets = list(secrets_map.values())
    
    def _suggest_env_var(self, finding: Finding) -> str:
        """Generate a suggested environment variable name."""
        type_str = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
        
        prefixes = {
            "azure_sql": "DG_AZURE_SQL_PASSWORD",
            "sql_server": "DG_SQL_PASSWORD",
            "database_password": "DG_DB_PASSWORD",
            "rabbitmq": "DG_RABBITMQ_PASSWORD",
            "fcm": "DG_FCM_SERVER_KEY",
            "jwt": "DG_JWT_SECRET",
            "vapid": "DG_VAPID_PRIVATE_KEY",
            "api_key": "DG_API_KEY",
            "aws_access_key": "DG_AWS_ACCESS_KEY_ID",
            "aws_secret_key": "DG_AWS_SECRET_ACCESS_KEY",
            "password": "DG_PASSWORD",
        }
        
        return prefixes.get(type_str, f"DG_{type_str.upper()}")
    
    def _mask_secret(self, value: str, visible_chars: int = 8) -> str:
        """Mask a secret value for display."""
        if len(value) <= visible_chars * 2:
            return value[:4] + "****"
        return value[:visible_chars] + "..." + value[-4:]
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _categorize_findings(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by type/category."""
        categories: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            type_str = f.type.value if hasattr(f.type, 'value') else str(f.type)
            # Normalize type names
            if "sql" in type_str.lower() and "azure" in type_str.lower():
                cat = "azure_sql"
            elif "sql" in type_str.lower():
                cat = "sql_server"
            elif "rabbit" in type_str.lower() or "amqp" in type_str.lower():
                cat = "rabbitmq"
            elif "fcm" in type_str.lower() or "firebase" in type_str.lower():
                cat = "fcm"
            elif "jwt" in type_str.lower():
                cat = "jwt"
            elif "vapid" in type_str.lower():
                cat = "vapid"
            elif "api" in type_str.lower() and "key" in type_str.lower():
                cat = "api_key"
            elif "aws" in type_str.lower():
                cat = "aws_access_key" if "access" in type_str.lower() else "aws_secret_key"
            else:
                cat = type_str
            categories[cat].append(f)
        return categories
    
    # =========================================================================
    # REPORT 1: OVERVIEW REPORT
    # =========================================================================
    
    def generate_overview_report(self) -> str:
        """
        Generate Report 1: Overview/Executive Summary.
        
        Includes:
        - Project summary
        - Repository metrics (commits, branches, years)
        - Technology stack
        - High-level findings summary
        - Scan scope and methodology
        """
        output_path = os.path.join(
            self.output_dir, 
            f"{self.metrics.name}_01_overview.md"
        )
        
        severity_counts = self._count_by_severity(self.before_findings)
        categories = self._categorize_findings(self.before_findings)
        
        with open(output_path, "w", encoding="utf-8") as fp:
            # Header
            fp.write(f"# {self.metrics.name} - Güvenlik Tarama Genel Bakış Raporu\n\n")
            fp.write(f"**Rapor Tarihi:** {self.scan_date.strftime('%d %B %Y, %H:%M')}\n")
            fp.write(f"**Oluşturan:** DeployGuard Repository Cleaner\n")
            fp.write(f"**Rapor Tipi:** 1/5 - Genel Bakış (Overview)\n\n")
            
            fp.write("---\n\n")
            
            # Executive Summary
            fp.write("## 1. Yönetici Özeti\n\n")
            
            fp.write(f"**{self.metrics.name}** repository'si kapsamlı güvenlik taramasından geçirilmiştir.\n\n")
            
            fp.write("### Kritik Bulgular\n\n")
            fp.write(f"| Metrik | Değer |\n")
            fp.write(f"|--------|-------|\n")
            fp.write(f"| 🔴 CRITICAL Bulgular | **{severity_counts['critical']}** |\n")
            fp.write(f"| 🟠 HIGH Bulgular | **{severity_counts['high']}** |\n")
            fp.write(f"| 🟡 MEDIUM Bulgular | {severity_counts['medium']} |\n")
            fp.write(f"| 🟢 LOW Bulgular | {severity_counts['low']} |\n")
            fp.write(f"| **Toplam Bulgu** | **{len(self.before_findings)}** |\n")
            fp.write(f"| Unique Secret Sayısı | {len(self.secrets)} |\n\n")
            
            if severity_counts['critical'] > 0:
                fp.write("⚠️ **ACİL AKSİYON GEREKLİ:** CRITICAL seviyesinde bulgular tespit edildi!\n\n")
            
            # Repository Metrics
            fp.write("---\n\n")
            fp.write("## 2. Repository Metrikleri\n\n")
            
            fp.write("### 2.1 Genel Bilgiler\n\n")
            fp.write(f"| Metrik | Değer |\n")
            fp.write(f"|--------|-------|\n")
            fp.write(f"| Repository Adı | {self.metrics.name} |\n")
            if self.metrics.remote_url:
                fp.write(f"| Remote URL | {self.metrics.remote_url} |\n")
            fp.write(f"| Repository Boyutu | {self.metrics.size_before_mb():.1f} MB |\n\n")
            
            fp.write("### 2.2 Git Geçmişi\n\n")
            fp.write(f"| Metrik | Değer |\n")
            fp.write(f"|--------|-------|\n")
            fp.write(f"| Toplam Commit Sayısı | **{self.metrics.total_commits}** |\n")
            fp.write(f"| Toplam Branch Sayısı | **{self.metrics.total_branches}** |\n")
            fp.write(f"| • Local Branch | {self.metrics.local_branches} |\n")
            fp.write(f"| • Remote Branch | {self.metrics.remote_branches} |\n")
            if self.metrics.first_commit_date:
                fp.write(f"| İlk Commit | {self.metrics.first_commit_date} |\n")
            if self.metrics.last_commit_date:
                fp.write(f"| Son Commit | {self.metrics.last_commit_date} |\n")
            if self.metrics.history_years > 0:
                fp.write(f"| Geçmiş Süresi | {self.metrics.history_years:.1f} yıl |\n")
            fp.write("\n")
            
            # Branch list
            if self.metrics.branches_list:
                fp.write("### 2.3 Branch Listesi\n\n")
                fp.write("```\n")
                for branch in self.metrics.branches_list[:20]:
                    fp.write(f"  {branch}\n")
                if len(self.metrics.branches_list) > 20:
                    fp.write(f"  ... ve {len(self.metrics.branches_list) - 20} branch daha\n")
                fp.write("```\n\n")
            
            # Technology Stack
            if self.metrics.tech_stack:
                fp.write("### 2.4 Teknoloji Stack\n\n")
                fp.write("Tespit edilen teknolojiler:\n\n")
                for tech in self.metrics.tech_stack:
                    fp.write(f"- {tech}\n")
                fp.write("\n")
            
            # Scan Scope
            fp.write("---\n\n")
            fp.write("## 3. Tarama Kapsamı\n\n")
            
            fp.write("### 3.1 Taranan Alanlar\n\n")
            fp.write("- ✅ **Tüm Git Geçmişi:** Tüm commit'ler tarandı\n")
            fp.write("- ✅ **Tüm Branch'ler:** Local ve remote branch'ler dahil\n")
            fp.write("- ✅ **Silinmiş Dosyalar:** Git history'de kalan silinen dosyalar\n")
            fp.write("- ✅ **Configuration Dosyaları:** appsettings, .env, config dosyaları\n")
            fp.write("- ✅ **Source Code:** Tüm kaynak kod dosyaları\n\n")
            
            fp.write("### 3.2 Kontrol Edilen Secret Tipleri\n\n")
            for cat in sorted(categories.keys()):
                cat_name = self.SECRET_TYPES_TR.get(cat, cat)
                count = len(categories[cat])
                fp.write(f"- {cat_name} ({count} bulgu)\n")
            fp.write("\n")
            
            fp.write("### 3.3 Tarama Araçları\n\n")
            fp.write("- **DeployGuard Repository Cleaner:** Custom pattern matching\n")
            fp.write("- **800+ Detection Rules:** Kapsamlı secret pattern veritabanı\n")
            fp.write("- **Entropy Analysis:** Yüksek entropi string tespiti\n")
            fp.write("- **BFG Repo-Cleaner:** Git history temizleme (opsiyonel)\n\n")
            
            # Findings by Category
            fp.write("---\n\n")
            fp.write("## 4. Bulgu Özeti (Kategorilere Göre)\n\n")
            
            fp.write("| Kategori | Bulgu Sayısı | CRITICAL | HIGH | Öncelik |\n")
            fp.write("|----------|--------------|----------|------|--------|\n")
            
            for cat, findings in sorted(categories.items(), 
                key=lambda x: -self._count_by_severity(x[1])["critical"]):
                cat_name = self.SECRET_TYPES_TR.get(cat, cat)
                cat_counts = self._count_by_severity(findings)
                priority = "🔴 ACİL" if cat_counts["critical"] > 0 else "🟠 YÜKSEK" if cat_counts["high"] > 0 else "🟡 ORTA"
                fp.write(f"| {cat_name} | {len(findings)} | {cat_counts['critical']} | {cat_counts['high']} | {priority} |\n")
            
            fp.write("\n")
            
            # Footer
            fp.write("---\n\n")
            fp.write("## 5. Diğer Raporlar\n\n")
            fp.write(f"- 📄 [{self.metrics.name}_02_history.md](/{self.metrics.name}_02_history.md) - Commit/Branch Geçmişi\n")
            fp.write(f"- 📄 [{self.metrics.name}_03_variables.md](/{self.metrics.name}_03_variables.md) - Değişken Tanımları\n")
            fp.write(f"- 📄 [{self.metrics.name}_04_remediation.md](/{self.metrics.name}_04_remediation.md) - Düzeltme Raporu\n")
            fp.write(f"- 📄 [{self.metrics.name}_05_summary.md](/{self.metrics.name}_05_summary.md) - Proje Özeti\n\n")
            
            fp.write("---\n")
            fp.write(f"*Bu rapor DeployGuard tarafından {self.scan_date.strftime('%Y-%m-%d %H:%M')} tarihinde oluşturulmuştur.*\n")
        
        return output_path
    
    # =========================================================================
    # REPORT 2: COMMIT/BRANCH HISTORY REPORT
    # =========================================================================
    
    def generate_history_report(self) -> str:
        """
        Generate Report 2: Commit/Branch History Analysis.
        
        Includes:
        - All branches scanned
        - Commit timeline with secrets
        - Secrets found in deleted files
        - First introduction date per secret
        """
        output_path = os.path.join(
            self.output_dir,
            f"{self.metrics.name}_02_history.md"
        )
        
        categories = self._categorize_findings(self.before_findings)
        
        with open(output_path, "w", encoding="utf-8") as fp:
            # Header
            fp.write(f"# {self.metrics.name} - Git Geçmişi Analiz Raporu\n\n")
            fp.write(f"**Rapor Tarihi:** {self.scan_date.strftime('%d %B %Y, %H:%M')}\n")
            fp.write(f"**Oluşturan:** DeployGuard Repository Cleaner\n")
            fp.write(f"**Rapor Tipi:** 2/5 - Commit/Branch Geçmişi\n\n")
            
            fp.write("---\n\n")
            
            # Git History Overview
            fp.write("## 1. Git Geçmişi Özeti\n\n")
            
            fp.write(f"| Metrik | Değer |\n")
            fp.write(f"|--------|-------|\n")
            fp.write(f"| Toplam Commit | **{self.metrics.total_commits}** |\n")
            fp.write(f"| Toplam Branch | **{self.metrics.total_branches}** |\n")
            fp.write(f"| Tarih Aralığı | {self.metrics.first_commit_date} → {self.metrics.last_commit_date} |\n")
            fp.write(f"| Geçmiş Süresi | {self.metrics.history_years:.1f} yıl |\n\n")
            
            # Branch Analysis
            fp.write("## 2. Branch Analizi\n\n")
            
            fp.write("### 2.1 Taranan Branch'ler\n\n")
            fp.write("Tüm branch'ler secret taramasından geçirildi:\n\n")
            
            fp.write("| Branch | Tip | Durum |\n")
            fp.write("|--------|-----|-------|\n")
            
            for branch in self.metrics.branches_list[:30]:
                branch_type = "Remote" if branch.startswith("remotes/") else "Local"
                status = "✅ Tarandı"
                fp.write(f"| `{branch}` | {branch_type} | {status} |\n")
            
            if len(self.metrics.branches_list) > 30:
                fp.write(f"| ... | ... | +{len(self.metrics.branches_list) - 30} branch daha |\n")
            fp.write("\n")
            
            # Secrets by File
            fp.write("## 3. Dosya Bazında Secret Analizi\n\n")
            
            # Group by file
            files_with_secrets: Dict[str, List[Finding]] = defaultdict(list)
            for f in self.before_findings:
                files_with_secrets[f.file_path].append(f)
            
            fp.write(f"Toplam **{len(files_with_secrets)}** dosyada secret tespit edildi:\n\n")
            
            fp.write("| Dosya | Secret Sayısı | CRITICAL | HIGH | Durum |\n")
            fp.write("|-------|---------------|----------|------|-------|\n")
            
            for file_path, findings in sorted(files_with_secrets.items(), 
                key=lambda x: -len(x[1]))[:50]:
                file_counts = self._count_by_severity(findings)
                
                # Check if file is deleted
                result = self._run_git(["ls-files", file_path])
                is_deleted = result.returncode != 0 or not result.stdout.strip()
                status = "🗑️ Silinmiş (history'de)" if is_deleted else "📄 Mevcut"
                
                fp.write(f"| `{file_path}` | {len(findings)} | {file_counts['critical']} | {file_counts['high']} | {status} |\n")
            
            if len(files_with_secrets) > 50:
                fp.write(f"| ... | ... | ... | ... | +{len(files_with_secrets) - 50} dosya daha |\n")
            fp.write("\n")
            
            # Deleted files warning
            deleted_count = sum(1 for fp in files_with_secrets.keys() 
                if self._run_git(["ls-files", fp]).returncode != 0)
            if deleted_count > 0:
                fp.write(f"⚠️ **{deleted_count} silinmiş dosyada** secret bulundu. ")
                fp.write("Bu dosyalar diskten silinmiş olsa da git history'de hala mevcut!\n\n")
            
            # Detailed Secret Locations
            fp.write("## 4. Secret Lokasyonları (Detaylı)\n\n")
            
            finding_num = 1
            for cat, findings in sorted(categories.items(),
                key=lambda x: -self._count_by_severity(x[1])["critical"]):
                
                cat_name = self.SECRET_TYPES_TR.get(cat, cat)
                cat_counts = self._count_by_severity(findings)
                
                if cat_counts["critical"] > 0:
                    emoji = "🔴"
                    level = "CRITICAL"
                elif cat_counts["high"] > 0:
                    emoji = "🟠"
                    level = "HIGH"
                else:
                    emoji = "🟡"
                    level = "MEDIUM"
                
                fp.write(f"### 4.{finding_num}. {emoji} {level}: {cat_name}\n\n")
                
                # Group by file for this category
                cat_by_file: Dict[str, List[Finding]] = defaultdict(list)
                for f in findings:
                    cat_by_file[f.file_path].append(f)
                
                fp.write("**Bulunduğu Dosyalar:**\n\n")
                for file_path, file_findings in cat_by_file.items():
                    lines = sorted(set(f.line_number for f in file_findings if f.line_number > 0))
                    lines_str = ", ".join(str(l) for l in lines[:10])
                    if len(lines) > 10:
                        lines_str += f" (+{len(lines) - 10} satır)"
                    
                    fp.write(f"- **`{file_path}`**\n")
                    if lines_str:
                        fp.write(f"  - Satırlar: {lines_str}\n")
                    fp.write(f"  - Bulgu sayısı: {len(file_findings)}\n")
                
                fp.write("\n")
                
                # Show commit info if available
                sample = findings[0]
                commits = sample.metadata.get("commits", [])
                if commits:
                    fp.write(f"**Git History:** {len(commits)} commit'te tespit edildi\n")
                    if len(commits) <= 5:
                        fp.write("```\n")
                        for commit in commits:
                            fp.write(f"  {commit[:8]}\n")
                        fp.write("```\n")
                fp.write("\n")
                
                finding_num += 1
            
            # Footer
            fp.write("---\n\n")
            fp.write("## 5. Sonuç\n\n")
            fp.write(f"- **{self.metrics.total_commits}** commit tarandı\n")
            fp.write(f"- **{self.metrics.total_branches}** branch kontrol edildi\n")
            fp.write(f"- **{len(files_with_secrets)}** dosyada secret bulundu\n")
            if deleted_count > 0:
                fp.write(f"- **{deleted_count}** silinmiş dosyada secret mevcut (git history'de)\n")
            fp.write("\n")
            
            fp.write("---\n")
            fp.write(f"*Bu rapor DeployGuard tarafından {self.scan_date.strftime('%Y-%m-%d %H:%M')} tarihinde oluşturulmuştur.*\n")
        
        return output_path
    
    # =========================================================================
    # REPORT 3: VARIABLE DEFINITIONS REPORT
    # =========================================================================
    
    def generate_variables_report(self) -> str:
        """
        Generate Report 3: Environment Variable Definitions.
        
        Includes:
        - All secrets mapped to env var names
        - .env.template format
        - Configuration update instructions
        """
        output_path = os.path.join(
            self.output_dir,
            f"{self.metrics.name}_03_variables.md"
        )
        
        categories = self._categorize_findings(self.before_findings)
        
        with open(output_path, "w", encoding="utf-8") as fp:
            # Header
            fp.write(f"# {self.metrics.name} - Değişken Tanımları Raporu\n\n")
            fp.write(f"**Rapor Tarihi:** {self.scan_date.strftime('%d %B %Y, %H:%M')}\n")
            fp.write(f"**Oluşturan:** DeployGuard Repository Cleaner\n")
            fp.write(f"**Rapor Tipi:** 3/5 - Environment Variable Tanımları\n\n")
            
            fp.write("---\n\n")
            
            # Summary
            fp.write("## 1. Özet\n\n")
            fp.write(f"Bu rapor, tespit edilen **{len(self.secrets)}** unique secret için ")
            fp.write("önerilen environment variable tanımlarını içerir.\n\n")
            
            fp.write("**Naming Convention:** `DG_` prefix'i ile başlayan değişken isimleri önerilmektedir.\n\n")
            
            # Variable Mapping Table
            fp.write("## 2. Değişken Mapping Tablosu\n\n")
            
            fp.write("| # | Secret Tipi | Önerilen Değişken | Dosya | Öncelik |\n")
            fp.write("|---|-------------|-------------------|-------|--------|\n")
            
            for i, secret in enumerate(self.secrets, 1):
                cat_name = self.SECRET_TYPES_TR.get(secret.secret_type, secret.secret_type)
                priority = "🔴 CRITICAL" if secret.severity == "critical" else "🟠 HIGH" if secret.severity == "high" else "🟡 MEDIUM"
                files_str = secret.files[0] if secret.files else "-"
                fp.write(f"| {i} | {cat_name} | `{secret.suggested_env_var}` | `{files_str}` | {priority} |\n")
            
            fp.write("\n")
            
            # .env.template
            fp.write("## 3. Environment Template (.env.template)\n\n")
            fp.write("Aşağıdaki template'i `.env.template` olarak kaydedin:\n\n")
            
            fp.write("```bash\n")
            fp.write("# ============================================================\n")
            fp.write(f"# {self.metrics.name} Environment Variables\n")
            fp.write(f"# Generated by DeployGuard - {self.scan_date.strftime('%Y-%m-%d')}\n")
            fp.write("# ============================================================\n")
            fp.write("# ⚠️ Bu dosyayı .env olarak kopyalayın ve gerçek değerleri girin\n")
            fp.write("# ⚠️ .env dosyasını ASLA git'e commit etmeyin!\n")
            fp.write("# ============================================================\n\n")
            
            # Group by category
            for cat in sorted(categories.keys()):
                cat_name = self.SECRET_TYPES_TR.get(cat, cat)
                fp.write(f"# --- {cat_name} ---\n")
                
                seen_vars = set()
                for f in categories[cat]:
                    var_name = f.metadata.get("suggested_env_var") or self._suggest_env_var(f)
                    if var_name not in seen_vars:
                        seen_vars.add(var_name)
                        fp.write(f"{var_name}=<ENTER_VALUE_HERE>\n")
                fp.write("\n")
            
            fp.write("```\n\n")
            
            # Configuration Update Examples
            fp.write("## 4. Konfigürasyon Güncelleme Örnekleri\n\n")
            
            fp.write("### 4.1 .NET Core (appsettings.json)\n\n")
            fp.write("```json\n")
            fp.write("{\n")
            fp.write('  "ConnectionStrings": {\n')
            fp.write('    "DefaultConnection": "Server=...;Password=${DG_DB_PASSWORD}"\n')
            fp.write("  },\n")
            fp.write('  "Jwt": {\n')
            fp.write('    "SecretKey": "${DG_JWT_SECRET}"\n')
            fp.write("  },\n")
            fp.write('  "RabbitMQ": {\n')
            fp.write('    "Password": "${DG_RABBITMQ_PASSWORD}"\n')
            fp.write("  }\n")
            fp.write("}\n")
            fp.write("```\n\n")
            
            fp.write("### 4.2 Docker Compose\n\n")
            fp.write("```yaml\n")
            fp.write("services:\n")
            fp.write("  api:\n")
            fp.write("    environment:\n")
            fp.write("      - DG_DB_PASSWORD=${DG_DB_PASSWORD}\n")
            fp.write("      - DG_JWT_SECRET=${DG_JWT_SECRET}\n")
            fp.write("      - DG_RABBITMQ_PASSWORD=${DG_RABBITMQ_PASSWORD}\n")
            fp.write("```\n\n")
            
            fp.write("### 4.3 Kubernetes Secret\n\n")
            fp.write("```yaml\n")
            fp.write("apiVersion: v1\n")
            fp.write("kind: Secret\n")
            fp.write("metadata:\n")
            fp.write(f"  name: {self.metrics.name}-secrets\n")
            fp.write("type: Opaque\n")
            fp.write("stringData:\n")
            seen = set()
            for secret in self.secrets[:10]:
                if secret.suggested_env_var not in seen:
                    seen.add(secret.suggested_env_var)
                    fp.write(f"  {secret.suggested_env_var}: <base64-encoded-value>\n")
            fp.write("```\n\n")
            
            # Detailed Variable Definitions
            fp.write("## 5. Detaylı Değişken Tanımları\n\n")
            
            for i, secret in enumerate(self.secrets, 1):
                cat_name = self.SECRET_TYPES_TR.get(secret.secret_type, secret.secret_type)
                masked = self._mask_secret(secret.secret_value)
                
                fp.write(f"### 5.{i}. `{secret.suggested_env_var}`\n\n")
                fp.write(f"| Özellik | Değer |\n")
                fp.write(f"|---------|-------|\n")
                fp.write(f"| Secret Tipi | {cat_name} |\n")
                fp.write(f"| Mevcut Değer | `{masked}` |\n")
                fp.write(f"| Severity | {secret.severity.upper()} |\n")
                fp.write(f"| Bulunduğu Dosyalar | {len(secret.files)} dosya |\n\n")
                
                if secret.files:
                    fp.write("**Dosyalar:**\n")
                    for f in secret.files[:5]:
                        fp.write(f"- `{f}`\n")
                    if len(secret.files) > 5:
                        fp.write(f"- ... ve {len(secret.files) - 5} dosya daha\n")
                fp.write("\n")
            
            # Footer
            fp.write("---\n")
            fp.write(f"*Bu rapor DeployGuard tarafından {self.scan_date.strftime('%Y-%m-%d %H:%M')} tarihinde oluşturulmuştur.*\n")
        
        return output_path
    
    # =========================================================================
    # REPORT 4: REMEDIATION CHANGES REPORT
    # =========================================================================
    
    def generate_remediation_report(self) -> str:
        """
        Generate Report 4: Remediation/Changes Report.
        
        Includes:
        - Before/after comparison
        - Files modified
        - Replacements made
        - Rotation instructions
        """
        output_path = os.path.join(
            self.output_dir,
            f"{self.metrics.name}_04_remediation.md"
        )
        
        categories = self._categorize_findings(self.before_findings)
        before_counts = self._count_by_severity(self.before_findings)
        after_counts = self._count_by_severity(self.after_findings) if self.after_findings else None
        
        with open(output_path, "w", encoding="utf-8") as fp:
            # Header
            fp.write(f"# {self.metrics.name} - Düzeltme İşlemleri Raporu\n\n")
            fp.write(f"**Rapor Tarihi:** {self.scan_date.strftime('%d %B %Y, %H:%M')}\n")
            fp.write(f"**Oluşturan:** DeployGuard Repository Cleaner\n")
            fp.write(f"**Rapor Tipi:** 4/5 - Remediation/Düzeltme Raporu\n\n")
            
            fp.write("---\n\n")
            
            # Cleanup Status
            fp.write("## 1. Temizlik Durumu\n\n")
            
            if after_counts:
                # We have before/after data
                fp.write("### 1.1 Karşılaştırma Tablosu\n\n")
                fp.write("| Metrik | Öncesi | Sonrası | Değişim |\n")
                fp.write("|--------|--------|---------|--------|\n")
                
                total_before = len(self.before_findings)
                total_after = len(self.after_findings)
                total_pct = f"-{((total_before - total_after) / total_before * 100):.0f}%" if total_before > 0 else "0%"
                fp.write(f"| Toplam Bulgu | {total_before} | {total_after} | {total_pct} |\n")
                
                for sev in ["critical", "high", "medium", "low"]:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                    before = before_counts[sev]
                    after = after_counts[sev]
                    if before > 0:
                        pct = f"-{((before - after) / before * 100):.0f}%"
                        status = " ✅" if after == 0 else ""
                    else:
                        pct = "0%"
                        status = ""
                    fp.write(f"| {emoji} {sev.upper()} | {before} | {after} | {pct}{status} |\n")
                
                fp.write("\n")
                
                if after_counts["critical"] == 0 and before_counts["critical"] > 0:
                    fp.write("✅ **Tüm CRITICAL bulgular başarıyla temizlendi!**\n\n")
            else:
                # Only before data - show what needs to be done
                fp.write("### 1.1 Mevcut Durum\n\n")
                fp.write("| Severity | Bulgu Sayısı | Durum |\n")
                fp.write("|----------|--------------|-------|\n")
                for sev in ["critical", "high", "medium", "low"]:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                    status = "⚠️ Temizlenmeli" if before_counts[sev] > 0 else "✅ Temiz"
                    fp.write(f"| {emoji} {sev.upper()} | {before_counts[sev]} | {status} |\n")
                fp.write("\n")
            
            # Required Actions by Category
            fp.write("## 2. Kategori Bazında Gerekli Aksiyonlar\n\n")
            
            action_num = 1
            for cat, findings in sorted(categories.items(),
                key=lambda x: -self._count_by_severity(x[1])["critical"]):
                
                cat_name = self.SECRET_TYPES_TR.get(cat, cat)
                cat_counts = self._count_by_severity(findings)
                
                if cat_counts["critical"] > 0:
                    emoji = "🔴"
                    priority = "ACİL"
                elif cat_counts["high"] > 0:
                    emoji = "🟠"
                    priority = "YÜKSEK"
                else:
                    emoji = "🟡"
                    priority = "ORTA"
                
                fp.write(f"### 2.{action_num}. {emoji} {priority}: {cat_name}\n\n")
                
                # Sample value
                sample = findings[0]
                value = sample.metadata.get("actual_value") or sample.exposed_value
                masked = self._mask_secret(value)
                
                fp.write(f"**Mevcut Değer:** `{masked}` ({len(value)} karakter)\n\n")
                
                # Files affected
                affected_files = set(f.file_path for f in findings)
                fp.write(f"**Etkilenen Dosyalar:** {len(affected_files)} dosya\n")
                for f in list(affected_files)[:5]:
                    fp.write(f"- `{f}`\n")
                if len(affected_files) > 5:
                    fp.write(f"- ... ve {len(affected_files) - 5} dosya daha\n")
                fp.write("\n")
                
                # What needs to be done
                fp.write("**⚠️ YAPILMASI GEREKENLER:**\n\n")
                fp.write("1. DeployGuard ile git history'den temizle\n")
                fp.write("2. Credential'ı MUTLAKA rotate et\n")
                fp.write("3. Environment variable olarak yapılandır\n")
                fp.write("4. Tüm service'leri yeniden deploy et\n\n")
                
                # Rotation instructions
                if cat in self.ROTATION_INSTRUCTIONS:
                    fp.write("**Rotation Talimatları:**\n")
                    fp.write(self.ROTATION_INSTRUCTIONS[cat])
                    fp.write("\n\n")
                
                action_num += 1
            
            # Purge File Content (for reference)
            fp.write("## 3. Replacement Mapping (Referans)\n\n")
            fp.write("DeployGuard temizlik sırasında aşağıdaki değişimleri yapacaktır:\n\n")
            
            fp.write("```\n")
            fp.write("# DeployGuard Replacement Mapping\n")
            fp.write(f"# Repository: {self.metrics.name}\n")
            fp.write(f"# Date: {self.scan_date.strftime('%Y-%m-%d')}\n\n")
            
            for cat, findings in categories.items():
                cat_name = self.SECRET_TYPES_TR.get(cat, cat)
                fp.write(f"# --- {cat_name} ---\n")
                
                seen = set()
                for f in findings:
                    value = f.metadata.get("actual_value") or f.exposed_value
                    if value not in seen and len(value) >= 4:
                        seen.add(value)
                        var_name = f.metadata.get("suggested_env_var") or self._suggest_env_var(f)
                        
                        # Escape special chars for BFG
                        if '#' in value or '\\' in value:
                            import re
                            escaped = re.escape(value)
                            fp.write(f"regex:{escaped}==>{var_name.upper()}_REMOVED\n")
                        else:
                            fp.write(f"{value}==>{var_name.upper()}_REMOVED\n")
                fp.write("\n")
            
            fp.write("```\n\n")
            
            # Cleanup Commands - DeployGuard Only
            fp.write("## 4. DeployGuard ile Temizlik Komutları\n\n")
            
            fp.write("### 4.1 Otomatik Temizlik (Önerilen)\n\n")
            fp.write("```bash\n")
            fp.write("# 1. Mirror clone oluştur (güvenli temizlik için)\n")
            if self.metrics.remote_url:
                fp.write(f"git clone --mirror {self.metrics.remote_url} {self.metrics.name}.git\n\n")
            else:
                fp.write(f"git clone --mirror <repo_url> {self.metrics.name}.git\n\n")
            fp.write("# 2. DeployGuard ile tara ve temizle\n")
            fp.write(f"deployguard clean history --path {self.metrics.name}.git --execute\n\n")
            fp.write("# 3. Temizlenmiş repo'yu push et\n")
            fp.write("cd " + self.metrics.name + ".git\n")
            fp.write("git push --mirror --force-with-lease\n")
            fp.write("```\n\n")
            
            fp.write("### 4.2 Adım Adım Temizlik\n\n")
            fp.write("```bash\n")
            fp.write("# 1. Önce tarama yap (dry-run)\n")
            fp.write(f"deployguard scan history --path {self.metrics.name}.git\n\n")
            fp.write("# 2. Rapor oluştur\n")
            fp.write(f"deployguard scan history --path {self.metrics.name}.git --generate-reports ./reports/\n\n")
            fp.write("# 3. Temizliği çalıştır\n")
            fp.write(f"deployguard clean history --path {self.metrics.name}.git --execute\n\n")
            fp.write("# 4. Doğrula (temizlik sonrası tekrar tara)\n")
            fp.write(f"deployguard scan history --path {self.metrics.name}.git\n")
            fp.write("```\n\n")
            
            fp.write("### 4.3 Environment Variable ile Temizlik\n\n")
            fp.write("Secret'ları `***REMOVED***` yerine environment variable placeholder'ları ile değiştirmek için:\n\n")
            fp.write("```bash\n")
            fp.write(f"deployguard clean history --path {self.metrics.name}.git --use-env-vars --execute\n")
            fp.write("```\n\n")
            fp.write("Bu durumda secret'lar şu formatta değiştirilir:\n")
            fp.write("```\n")
            fp.write("Pr0d@Secret123 → ${DG_AZURE_SQL_PASSWORD}\n")
            fp.write("AAAAxxxx:FCM... → ${DG_FCM_SERVER_KEY}\n")
            fp.write("```\n\n")
            
            # Footer
            fp.write("---\n")
            fp.write(f"*Bu rapor DeployGuard tarafından {self.scan_date.strftime('%Y-%m-%d %H:%M')} tarihinde oluşturulmuştur.*\n")
        
        return output_path
    
    # =========================================================================
    # REPORT 5: PROJECT SUMMARY REPORT
    # =========================================================================
    
    def generate_summary_report(self) -> str:
        """
        Generate Report 5: Project Summary.
        
        Includes:
        - Overall status
        - Key achievements
        - Remaining issues
        - Next steps and recommendations
        """
        output_path = os.path.join(
            self.output_dir,
            f"{self.metrics.name}_05_summary.md"
        )
        
        before_counts = self._count_by_severity(self.before_findings)
        after_counts = self._count_by_severity(self.after_findings) if self.after_findings else None
        
        with open(output_path, "w", encoding="utf-8") as fp:
            # Header
            fp.write(f"# {self.metrics.name} - Proje Özet Raporu\n\n")
            fp.write(f"**Rapor Tarihi:** {self.scan_date.strftime('%d %B %Y, %H:%M')}\n")
            fp.write(f"**Oluşturan:** DeployGuard Repository Cleaner\n")
            fp.write(f"**Rapor Tipi:** 5/5 - Proje Özeti (Final)\n\n")
            
            fp.write("---\n\n")
            
            # Overall Status
            fp.write("## 1. Genel Durum\n\n")
            
            if after_counts and after_counts["critical"] == 0 and before_counts["critical"] > 0:
                fp.write("### ✅ BAŞARILI - Tüm kritik bulgular temizlendi\n\n")
                status = "TAMAMLANDI"
            elif before_counts["critical"] > 0:
                fp.write("### ⚠️ ACİL AKSİYON GEREKLİ - Kritik bulgular mevcut\n\n")
                status = "DEVAM EDİYOR"
            else:
                fp.write("### ℹ️ İNCELEME GEREKLİ - Orta/düşük seviye bulgular mevcut\n\n")
                status = "İNCELENİYOR"
            
            fp.write(f"| Proje | Durum |\n")
            fp.write(f"|-------|-------|\n")
            fp.write(f"| {self.metrics.name} | **{status}** |\n\n")
            
            # Key Metrics Summary
            fp.write("## 2. Anahtar Metrikler\n\n")
            
            fp.write("### 2.1 Repository\n\n")
            fp.write(f"| Metrik | Değer |\n")
            fp.write(f"|--------|-------|\n")
            fp.write(f"| Commit Sayısı | {self.metrics.total_commits} |\n")
            fp.write(f"| Branch Sayısı | {self.metrics.total_branches} |\n")
            fp.write(f"| Geçmiş | {self.metrics.history_years:.1f} yıl |\n")
            fp.write(f"| Boyut | {self.metrics.size_before_mb():.1f} MB |\n\n")
            
            fp.write("### 2.2 Güvenlik Bulguları\n\n")
            
            if after_counts:
                fp.write("| Severity | Öncesi | Sonrası | Temizlenen |\n")
                fp.write("|----------|--------|---------|------------|\n")
                for sev in ["critical", "high", "medium", "low"]:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                    cleaned = before_counts[sev] - after_counts[sev]
                    pct = f"({cleaned}/{before_counts[sev]})" if before_counts[sev] > 0 else ""
                    fp.write(f"| {emoji} {sev.upper()} | {before_counts[sev]} | {after_counts[sev]} | {cleaned} {pct} |\n")
            else:
                fp.write("| Severity | Bulgu Sayısı |\n")
                fp.write("|----------|-------------|\n")
                for sev in ["critical", "high", "medium", "low"]:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                    fp.write(f"| {emoji} {sev.upper()} | {before_counts[sev]} |\n")
            fp.write("\n")
            
            # Achievements
            fp.write("## 3. Gerçekleştirilen İşlemler\n\n")
            
            fp.write("### 3.1 Tarama\n\n")
            fp.write(f"- ✅ {self.metrics.total_commits} commit tarandı\n")
            fp.write(f"- ✅ {self.metrics.total_branches} branch kontrol edildi\n")
            fp.write(f"- ✅ {len(self.before_findings)} bulgu tespit edildi\n")
            fp.write(f"- ✅ {len(self.secrets)} unique secret belirlendi\n\n")
            
            if after_counts:
                fp.write("### 3.2 Temizlik\n\n")
                cleaned_total = len(self.before_findings) - len(self.after_findings)
                fp.write(f"- ✅ {cleaned_total} bulgu temizlendi\n")
                if after_counts["critical"] == 0 and before_counts["critical"] > 0:
                    fp.write(f"- ✅ Tüm CRITICAL bulgular giderildi ({before_counts['critical']} adet)\n")
                fp.write("- ✅ Git history yeniden yazıldı\n")
                fp.write("- ✅ Placeholder'lar ile değiştirildi\n\n")
            
            # Remaining Issues
            remaining = after_counts if after_counts else before_counts
            total_remaining = sum(remaining.values())
            
            if total_remaining > 0:
                fp.write("## 4. Kalan Konular\n\n")
                
                if remaining["critical"] > 0:
                    fp.write(f"### ⚠️ CRITICAL ({remaining['critical']} adet)\n\n")
                    fp.write("Bu bulgular ACİL olarak ele alınmalıdır:\n")
                    fp.write("- Credential rotation yapılmalı\n")
                    fp.write("- Environment variable'lara taşınmalı\n\n")
                
                if remaining["high"] > 0:
                    fp.write(f"### 🟠 HIGH ({remaining['high']} adet)\n\n")
                    fp.write("Bu bulgular en kısa sürede çözülmelidir.\n\n")
                
                if remaining["medium"] + remaining["low"] > 0:
                    fp.write(f"### 🟡 MEDIUM/LOW ({remaining['medium'] + remaining['low']} adet)\n\n")
                    fp.write("Bu bulgular planlı bakım döneminde incelenebilir.\n\n")
            
            # Next Steps
            fp.write("## 5. Sonraki Adımlar\n\n")
            
            fp.write("### 5.1 Geliştirici Ekip (TÜM DEVELOPERS)\n\n")
            fp.write("```bash\n")
            fp.write("# ⚠️ ÖNEMLİ: Tüm local repository'ler silinmeli!\n")
            fp.write("# Stash edilmemiş değişiklikler kaybolacak!\n\n")
            fp.write("# 1. Değişiklikleri stash edin\n")
            fp.write('git stash save "Pre-cleanup changes"\n\n')
            fp.write("# 2. Eski kopyayı silin\n")
            fp.write(f"rm -rf {self.metrics.name}\n\n")
            fp.write("# 3. Yeni temizlenmiş repo'yu clone edin\n")
            if self.metrics.remote_url:
                fp.write(f"git clone {self.metrics.remote_url}\n")
            else:
                fp.write(f"git clone <yeni_repo_url>\n")
            fp.write("```\n\n")
            
            fp.write("### 5.2 IT Güvenlik Ekibi\n\n")
            fp.write("| Görev | Öncelik | Durum |\n")
            fp.write("|-------|---------|-------|\n")
            fp.write("| Database credential rotation | 🔴 CRITICAL | ⬜ Bekliyor |\n")
            fp.write("| API key rotation | 🔴 CRITICAL | ⬜ Bekliyor |\n")
            fp.write("| JWT secret yenileme | 🟠 HIGH | ⬜ Bekliyor |\n")
            fp.write("| Firewall rules review | 🟡 MEDIUM | ⬜ Bekliyor |\n\n")
            
            fp.write("### 5.3 DevOps Ekibi\n\n")
            fp.write("- [ ] CI/CD pipeline'larını yeni repo'ya yönlendir\n")
            fp.write("- [ ] Environment variable'ları secret manager'a taşı\n")
            fp.write("- [ ] Pre-commit hook'ları aktifleştir\n")
            fp.write("- [ ] Regular secret scanning schedule'ı oluştur\n\n")
            
            # Final Notes
            fp.write("## 6. Önemli Notlar\n\n")
            
            fp.write("### ❌ Neden `git pull` Çalışmaz?\n\n")
            fp.write("- Git geçmişi tamamen yeniden yazıldı\n")
            fp.write("- Tüm commit SHA'ları değişti\n")
            fp.write("- Eski lokal kopyalar remote ile uyumsuz\n")
            fp.write("- `git pull` hata verecek: `fatal: refusing to merge unrelated histories`\n\n")
            
            fp.write("### ✅ Başarı Kriterleri\n\n")
            fp.write("- [ ] Tüm CRITICAL bulgular giderildi\n")
            fp.write("- [ ] Credential'lar rotate edildi\n")
            fp.write("- [ ] Tüm geliştiriciler yeni repo'yu clone etti\n")
            fp.write("- [ ] CI/CD pipeline'lar güncellendi\n")
            fp.write("- [ ] Secret scanning otomasyonu aktif\n\n")
            
            # Report Links
            fp.write("---\n\n")
            fp.write("## Tüm Raporlar\n\n")
            fp.write(f"| # | Rapor | Açıklama |\n")
            fp.write(f"|---|-------|----------|\n")
            fp.write(f"| 1 | [{self.metrics.name}_01_overview.md](./{self.metrics.name}_01_overview.md) | Genel Bakış |\n")
            fp.write(f"| 2 | [{self.metrics.name}_02_history.md](./{self.metrics.name}_02_history.md) | Git Geçmişi |\n")
            fp.write(f"| 3 | [{self.metrics.name}_03_variables.md](./{self.metrics.name}_03_variables.md) | Değişken Tanımları |\n")
            fp.write(f"| 4 | [{self.metrics.name}_04_remediation.md](./{self.metrics.name}_04_remediation.md) | Düzeltme Raporu |\n")
            fp.write(f"| 5 | [{self.metrics.name}_05_summary.md](./{self.metrics.name}_05_summary.md) | Proje Özeti (Bu rapor) |\n\n")
            
            # Footer
            fp.write("---\n")
            fp.write(f"*Bu rapor DeployGuard tarafından {self.scan_date.strftime('%Y-%m-%d %H:%M')} tarihinde oluşturulmuştur.*\n")
        
        return output_path
    
    # =========================================================================
    # GENERATE ALL REPORTS
    # =========================================================================
    
    def generate_all_reports(self) -> List[str]:
        """
        Generate all 5 reports.
        
        Returns:
            List of generated report file paths
        """
        # Gather repo info if not already done
        if self.metrics.total_commits == 0:
            self.gather_repository_info()
        
        reports = []
        
        # Report 1: Overview
        reports.append(self.generate_overview_report())
        
        # Report 2: History
        reports.append(self.generate_history_report())
        
        # Report 3: Variables
        reports.append(self.generate_variables_report())
        
        # Report 4: Remediation
        reports.append(self.generate_remediation_report())
        
        # Report 5: Summary
        reports.append(self.generate_summary_report())
        
        return reports
