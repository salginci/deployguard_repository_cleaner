"""
DeployGuard CLI - Scan Command

Provides commands for scanning repositories for secrets with:
- Comprehensive detection of hardcoded values
- Detailed variable name and value reporting
- Export to various formats (JSON, CSV, HTML, Markdown, BFG)
- Interactive selection for masking
- Gitleaks-compatible output
- Multi-report generation (Turkish-style audit reports)
"""
import os
import json
import csv
import click
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from deployguard.core.scanner import SecretScanner
from deployguard.core.history_cleaner import GitHistoryCleaner, SecretMatch
from deployguard.core.models import Severity, Finding
from deployguard.cli.report_generator import ReportGenerator, RepositoryInfo
from deployguard.cli.multi_report_generator import MultiReportGenerator


@click.group()
def scan():
    """🔍 Scan repositories for exposed secrets."""
    pass


def format_finding_table(findings: List[Finding]) -> None:
    """Display findings in a formatted table with variable names and values."""
    if not findings:
        click.echo("\n✅ No secrets or hardcoded values found!")
        return
    
    click.echo("\n" + "=" * 100)
    click.echo("DETAILED FINDINGS")
    click.echo("=" * 100)
    click.echo(f"{'#':<4} {'SEV':<8} {'TYPE':<18} {'VARIABLE':<25} {'VALUE':<30} {'FILE:LINE':<30}")
    click.echo("-" * 100)
    
    for i, finding in enumerate(findings, 1):
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢"
        }
        severity_val = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        emoji = severity_emoji.get(severity_val, "⚪")
        
        # Extract variable name and value from metadata
        var_name = finding.metadata.get("variable_name", finding.suggested_variable) or "-"
        actual_value = finding.metadata.get("actual_value", "")
        
        # Truncate and mask value for display
        if actual_value:
            if len(actual_value) > 25:
                display_value = actual_value[:10] + "..." + actual_value[-8:]
            else:
                display_value = actual_value
        else:
            display_value = finding.exposed_value[:25] + "..." if len(finding.exposed_value) > 25 else finding.exposed_value
        
        file_loc = f"{Path(finding.file_path).name}:{finding.line_number}"
        
        # Handle both enum and string types for severity and type
        severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        type_str = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
        
        click.echo(
            f"{i:<4} {emoji} {severity_str:<6} {type_str:<18} "
            f"{var_name:<25} {display_value:<30} {file_loc:<30}"
        )


def export_findings_json(findings: List[Finding], output_path: str, scan_path: str) -> None:
    """Export findings to JSON format."""
    data = {
        "scan_date": datetime.now().isoformat(),
        "scanned_path": os.path.abspath(scan_path),
        "total_findings": len(findings),
        "findings": [
            {
                "id": i + 1,
                "type": f.type.value if hasattr(f.type, 'value') else str(f.type),
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "file_path": f.file_path,
                "line_number": f.line_number,
                "variable_name": f.metadata.get("variable_name") or f.suggested_variable,
                "actual_value": f.metadata.get("actual_value") or f.exposed_value,
                "full_match": f.exposed_value,
                "suggested_env_var": f.suggested_variable,
                "description": f.description,
                "remediation": f.remediation,
                "context": f.context,
            }
            for i, f in enumerate(findings)
        ],
    }
    
    with open(output_path, "w") as fp:
        json.dump(data, fp, indent=2)


def export_findings_csv(findings: List[Finding], output_path: str) -> None:
    """Export findings to CSV format."""
    with open(output_path, "w", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow([
            "ID", "Severity", "Type", "Variable Name", "Actual Value", 
            "Suggested Env Var", "File", "Line", "Description"
        ])
        
        for i, f in enumerate(findings, 1):
            writer.writerow([
                i,
                f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                f.type.value if hasattr(f.type, 'value') else str(f.type),
                f.metadata.get("variable_name") or f.suggested_variable or "-",
                f.metadata.get("actual_value") or f.exposed_value,
                f.suggested_variable or "-",
                f.file_path,
                f.line_number,
                f.description,
            ])


def export_findings_purge(findings: List[Finding], output_path: str, use_env_vars: bool = False) -> None:
    """Export findings as secrets_to_purge.txt (BFG-compatible format)."""
    with open(output_path, "w") as fp:
        fp.write("# Secrets to purge - Generated by DeployGuard\n")
        fp.write(f"# Generated: {datetime.now().isoformat()}\n")
        fp.write("# Format: secret_value==>replacement (or just secret_value for ***REMOVED***)\n\n")
        
        seen_values = set()
        for f in findings:
            value = f.metadata.get("actual_value") or f.exposed_value
            if value and value not in seen_values:
                seen_values.add(value)
                if use_env_vars and f.suggested_variable:
                    fp.write(f"{value}==>${{{f.suggested_variable}}}\n")
                else:
                    fp.write(f"{value}\n")


def export_env_template(findings: List[Finding], output_path: str) -> None:
    """Generate .env.template file with suggested variable names."""
    env_vars = {}
    
    for f in findings:
        var_name = f.metadata.get("variable_name") or f.suggested_variable
        if var_name and var_name not in env_vars:
            env_vars[var_name] = {
                "type": f.type.value if hasattr(f.type, 'value') else str(f.type),
                "description": f.description,
                "files": [f.file_path],
            }
        elif var_name and var_name in env_vars:
            if f.file_path not in env_vars[var_name]["files"]:
                env_vars[var_name]["files"].append(f.file_path)
    
    with open(output_path, "w") as fp:
        fp.write("# Environment Variables Template\n")
        fp.write("# Generated by DeployGuard Repository Cleaner\n")
        fp.write(f"# Generated: {datetime.now().isoformat()}\n")
        fp.write("# Replace placeholder values with actual secrets\n\n")
        
        for var_name, info in sorted(env_vars.items()):
            fp.write(f"# Type: {info['type']}\n")
            fp.write(f"# Found in: {', '.join(info['files'][:3])}\n")
            fp.write(f"{var_name}=your_value_here\n\n")


def export_findings_html(findings: List[Finding], output_path: str, scan_path: str, show_values: bool = False) -> None:
    """Export findings as an interactive HTML report."""
    import html as html_module
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Group findings by file
    findings_by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.file_path not in findings_by_file:
            findings_by_file[f.file_path] = []
        findings_by_file[f.file_path].append(f)
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DeployGuard Security Scan Report</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .subtitle {{ color: rgba(255,255,255,0.8); font-size: 1.1em; }}
        .meta {{ margin-top: 15px; font-size: 0.9em; color: rgba(255,255,255,0.7); }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--bg-card);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            border-left: 4px solid;
        }}
        .stat-card.critical {{ border-color: var(--critical); }}
        .stat-card.high {{ border-color: var(--high); }}
        .stat-card.medium {{ border-color: var(--medium); }}
        .stat-card.low {{ border-color: var(--low); }}
        .stat-card.total {{ border-color: #667eea; }}
        .stat-number {{ font-size: 3em; font-weight: bold; }}
        .stat-label {{ color: var(--text-secondary); text-transform: uppercase; font-size: 0.85em; letter-spacing: 1px; }}
        
        .filters {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 30px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .filters label {{ color: var(--text-secondary); }}
        .filters select, .filters input {{
            background: var(--bg-dark);
            border: 1px solid #333;
            color: var(--text-primary);
            padding: 10px 15px;
            border-radius: 6px;
            font-size: 1em;
        }}
        .filters input {{ flex: 1; min-width: 200px; }}
        
        .findings-section {{ margin-bottom: 30px; }}
        .file-group {{
            background: var(--bg-card);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }}
        .file-header {{
            background: rgba(255,255,255,0.05);
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .file-header:hover {{ background: rgba(255,255,255,0.08); }}
        .file-name {{ font-family: monospace; font-size: 0.95em; }}
        .file-count {{
            background: #667eea;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
        }}
        .file-findings {{ display: none; }}
        .file-findings.open {{ display: block; }}
        
        .finding {{
            padding: 20px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .finding:last-child {{ border-bottom: none; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }}
        .finding-type {{ font-weight: 600; font-size: 1.1em; }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); color: #000; }}
        .severity-badge.medium {{ background: var(--medium); color: #000; }}
        .severity-badge.low {{ background: var(--low); }}
        
        .finding-details {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }}
        .detail-item {{ background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px; }}
        .detail-label {{ color: var(--text-secondary); font-size: 0.85em; margin-bottom: 5px; display: flex; align-items: center; gap: 8px; }}
        .detail-value {{ font-family: monospace; word-break: break-all; }}
        .detail-value.masked-value {{ color: var(--high); }}
        .detail-value.actual-value {{ color: #4ade80; }}
        
        .reveal-btn {{
            background: transparent;
            border: 1px solid rgba(255,255,255,0.2);
            color: var(--text-secondary);
            cursor: pointer;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85em;
            transition: all 0.2s;
        }}
        .reveal-btn:hover {{ background: rgba(255,255,255,0.1); color: var(--text-primary); }}
        
        .toggle-values-btn {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            color: white;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 500;
            transition: all 0.2s;
        }}
        .toggle-values-btn:hover {{ transform: scale(1.05); box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); }}
        .toggle-values-btn.revealed {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }}
        
        .context-code {{
            background: #0d1117;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            margin-top: 15px;
        }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
        }}
        footer a {{ color: #667eea; text-decoration: none; }}
        
        .toggle-icon {{ transition: transform 0.3s; }}
        .file-header.open .toggle-icon {{ transform: rotate(90deg); }}
        
        @media (max-width: 768px) {{
            .stat-number {{ font-size: 2em; }}
            .finding-details {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ DeployGuard Security Report</h1>
            <p class="subtitle">Secret Detection Scan Results</p>
            <div class="meta">
                <p>📁 Scanned: <strong>{scan_path}</strong></p>
                <p>📅 Generated: <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong></p>
                <p>📊 Files with findings: <strong>{len(findings_by_file)}</strong></p>
            </div>
        </header>
        
        <div class="summary">
            <div class="stat-card critical">
                <div class="stat-number">{severity_counts["critical"]}</div>
                <div class="stat-label">🔴 Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{severity_counts["high"]}</div>
                <div class="stat-label">🟠 High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{severity_counts["medium"]}</div>
                <div class="stat-label">🟡 Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{severity_counts["low"]}</div>
                <div class="stat-label">🟢 Low</div>
            </div>
            <div class="stat-card total">
                <div class="stat-number">{len(findings)}</div>
                <div class="stat-label">📝 Total</div>
            </div>
        </div>
        
        <div class="filters">
            <label>Filter:</label>
            <select id="severityFilter" onchange="filterFindings()">
                <option value="all">All Severities</option>
                <option value="critical">Critical Only</option>
                <option value="high">High & Above</option>
                <option value="medium">Medium & Above</option>
            </select>
            <input type="text" id="searchInput" placeholder="Search by file, type, or value..." onkeyup="filterFindings()">
            <button id="toggleValuesBtn" class="toggle-values-btn" onclick="toggleAllValues()">
                🔓 Show Values
            </button>
        </div>
        
        <div class="findings-section" id="findingsContainer">
'''
    
    # Generate findings HTML grouped by file
    for file_path, file_findings in sorted(findings_by_file.items()):
        # Get relative path for display
        rel_path = file_path
        if scan_path and file_path.startswith(scan_path):
            rel_path = file_path[len(scan_path):].lstrip('/')
        
        html_content += f'''
            <div class="file-group" data-file="{rel_path.lower()}">
                <div class="file-header" onclick="toggleFile(this)">
                    <span class="file-name">📄 {rel_path}</span>
                    <span class="file-count">{len(file_findings)} finding{"s" if len(file_findings) != 1 else ""}</span>
                    <span class="toggle-icon">▶</span>
                </div>
                <div class="file-findings">
'''
        
        for f in file_findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            typ = f.type.value if hasattr(f.type, 'value') else str(f.type)
            var_name = f.metadata.get("variable_name") or f.suggested_variable or "-"
            actual_value = f.metadata.get("actual_value") or f.exposed_value
            masked_value = f.mask_value() if hasattr(f, 'mask_value') else actual_value[:4] + "****"
            
            # Escape HTML
            context_escaped = html_module.escape(f.context) if f.context else ""
            desc_escaped = html_module.escape(f.description) if f.description else ""
            remediation_escaped = html_module.escape(f.remediation) if f.remediation else ""
            actual_escaped = html_module.escape(actual_value)
            masked_escaped = html_module.escape(masked_value)
            
            # Determine initial display based on show_values flag
            masked_style = "display:none" if show_values else "display:inline"
            actual_style = "display:inline" if show_values else "display:none"
            
            html_content += f'''
                    <div class="finding" data-severity="{sev}" data-type="{typ.lower()}">
                        <div class="finding-header">
                            <span class="finding-type">{typ.replace("_", " ").title()}</span>
                            <span class="severity-badge {sev}">{sev}</span>
                        </div>
                        <div class="finding-details">
                            <div class="detail-item">
                                <div class="detail-label">Variable Name</div>
                                <div class="detail-value">{html_module.escape(var_name)}</div>
                            </div>
                            <div class="detail-item value-container">
                                <div class="detail-label">Exposed Value 
                                    <button class="reveal-btn" onclick="toggleValue(this)" title="Click to reveal/hide">👁️</button>
                                </div>
                                <div class="detail-value masked-value" style="{masked_style}">{masked_escaped}</div>
                                <div class="detail-value actual-value" style="{actual_style}">{actual_escaped}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Location</div>
                                <div class="detail-value">Line {f.line_number}, Column {f.column_start}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Suggested Env Variable</div>
                                <div class="detail-value">{html_module.escape(f.suggested_variable or "N/A")}</div>
                            </div>
                        </div>
                        {"<div class='detail-item' style='margin-top:15px'><div class='detail-label'>Description</div><div class='detail-value'>" + desc_escaped + "</div></div>" if desc_escaped else ""}
                        {"<div class='detail-item' style='margin-top:10px'><div class='detail-label'>Remediation</div><div class='detail-value'>" + remediation_escaped + "</div></div>" if remediation_escaped else ""}
                        {"<div class='context-code'>" + context_escaped + "</div>" if context_escaped else ""}
                    </div>
'''
        
        html_content += '''
                </div>
            </div>
'''
    
    html_content += '''
        </div>
        
        <footer>
            <p>Generated by <a href="https://github.com/deployguard">DeployGuard Repository Cleaner</a></p>
            <p>🔒 Keep your secrets safe!</p>
        </footer>
    </div>
    
    <script>
        function toggleFile(header) {
            header.classList.toggle('open');
            const findings = header.nextElementSibling;
            findings.classList.toggle('open');
        }
        
        function toggleValue(btn) {
            const container = btn.closest('.value-container');
            const masked = container.querySelector('.masked-value');
            const actual = container.querySelector('.actual-value');
            
            if (masked.style.display === 'none') {
                masked.style.display = 'inline';
                actual.style.display = 'none';
                btn.textContent = '👁️';
            } else {
                masked.style.display = 'none';
                actual.style.display = 'inline';
                btn.textContent = '🔒';
            }
        }
        
        let allValuesRevealed = ''' + ('true' if show_values else 'false') + ''';
        
        function toggleAllValues() {
            allValuesRevealed = !allValuesRevealed;
            const btn = document.getElementById('toggleValuesBtn');
            const maskedValues = document.querySelectorAll('.masked-value');
            const actualValues = document.querySelectorAll('.actual-value');
            const revealBtns = document.querySelectorAll('.reveal-btn');
            
            if (allValuesRevealed) {
                btn.textContent = '🔒 Hide Values';
                btn.classList.add('revealed');
                maskedValues.forEach(el => el.style.display = 'none');
                actualValues.forEach(el => el.style.display = 'inline');
                revealBtns.forEach(btn => btn.textContent = '🔒');
            } else {
                btn.textContent = '🔓 Show Values';
                btn.classList.remove('revealed');
                maskedValues.forEach(el => el.style.display = 'inline');
                actualValues.forEach(el => el.style.display = 'none');
                revealBtns.forEach(btn => btn.textContent = '👁️');
            }
        }
        
        function filterFindings() {
            const severity = document.getElementById('severityFilter').value;
            const search = document.getElementById('searchInput').value.toLowerCase();
            const fileGroups = document.querySelectorAll('.file-group');
            
            const severityOrder = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1};
            const minLevel = severity === 'all' ? 0 : 
                            severity === 'critical' ? 4 :
                            severity === 'high' ? 3 : 2;
            
            fileGroups.forEach(group => {
                const fileName = group.dataset.file;
                const findings = group.querySelectorAll('.finding');
                let visibleCount = 0;
                
                findings.forEach(finding => {
                    const findingSev = finding.dataset.severity;
                    const findingType = finding.dataset.type;
                    const text = finding.textContent.toLowerCase();
                    
                    const sevMatch = severityOrder[findingSev] >= minLevel;
                    const searchMatch = !search || fileName.includes(search) || 
                                       findingType.includes(search) || text.includes(search);
                    
                    if (sevMatch && searchMatch) {
                        finding.style.display = 'block';
                        visibleCount++;
                    } else {
                        finding.style.display = 'none';
                    }
                });
                
                group.style.display = visibleCount > 0 ? 'block' : 'none';
                group.querySelector('.file-count').textContent = visibleCount + ' finding' + (visibleCount !== 1 ? 's' : '');
            });
        }
        
        // Expand first file group by default if there are findings
        document.addEventListener('DOMContentLoaded', () => {
            const firstHeader = document.querySelector('.file-header');
            if (firstHeader) toggleFile(firstHeader);
            
            // Update button state based on initial show_values
            if (allValuesRevealed) {
                const btn = document.getElementById('toggleValuesBtn');
                btn.textContent = '🔒 Hide Values';
                btn.classList.add('revealed');
            }
        });
    </script>
</body>
</html>
'''
    
    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(html_content)


@scan.command("local")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to local repository or directory to scan"
)
@click.option(
    "--patterns", "-c",
    type=click.Path(exists=True),
    help="Path to custom patterns YAML file"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file for results (auto-detects format from extension: .json, .csv)"
)
@click.option(
    "--export-purge",
    type=click.Path(),
    help="Export secrets_to_purge.txt file for BFG cleaning"
)
@click.option(
    "--export-env",
    type=click.Path(),
    help="Export .env.template file with suggested variable names"
)
@click.option(
    "--export-html",
    type=click.Path(),
    help="Export interactive HTML report"
)
@click.option(
    "--export-markdown",
    type=click.Path(),
    help="Export Markdown executive summary report"
)
@click.option(
    "--export-gitleaks",
    type=click.Path(),
    help="Export Gitleaks-compatible JSON format"
)
@click.option(
    "--export-bfg",
    type=click.Path(),
    help="Export BFG Repo-Cleaner purge file with placeholders"
)
@click.option(
    "--export-detailed",
    type=click.Path(),
    help="Export detailed project report (like Smartgo format)"
)
@click.option(
    "--compare-baseline",
    type=click.Path(exists=True),
    help="Compare with baseline scan (JSON file) to track cleanup progress"
)
@click.option(
    "--language",
    type=click.Choice(["tr", "en"]),
    default="tr",
    help="Report language (Turkish or English)"
)
@click.option(
    "--show-values/--mask-values",
    default=False,
    help="Show actual secret values (default: masked for security)"
)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity level to report"
)
@click.option(
    "--include-history/--no-history",
    default=False,
    help="Also scan git history (all commits)"
)
@click.option(
    "--interactive/--no-interactive",
    default=False,
    help="Interactive mode: select which findings to mask"
)
@click.option(
    "--use-env-vars/--use-removed",
    default=True,
    help="Use ${VAR_NAME} placeholders instead of ***REMOVED***"
)
@click.pass_context
def scan_local(ctx, path: str, patterns: Optional[str], output: Optional[str], 
               export_purge: Optional[str], export_env: Optional[str], export_html: Optional[str],
               export_markdown: Optional[str], export_gitleaks: Optional[str], export_bfg: Optional[str],
               export_detailed: Optional[str], compare_baseline: Optional[str], language: str,
               show_values: bool, min_severity: str, include_history: bool, interactive: bool, use_env_vars: bool):
    """
    Scan a local directory or repository for secrets and hardcoded values.
    
    Detects:
    • Passwords, API keys, tokens
    • Database credentials (host, user, password, port, name)
    • Hostnames, IP addresses, URLs
    • Any hardcoded configuration values
    
    Export Formats:
    • JSON: Standard findings export
    • CSV: Spreadsheet format
    • HTML: Interactive report with filtering
    • Markdown: Executive summary report (Turkish/English)
    • Gitleaks: Gitleaks-compatible JSON for integration
    • BFG: secrets_to_purge.txt for BFG Repo-Cleaner
    • Detailed: Full project report (like Smartgo format)
    
    Examples:
        deployguard scan local --path /path/to/repo
        deployguard scan local --path . --output findings.json
        deployguard scan local -p ./myproject --export-bfg secrets.txt
        deployguard scan local -p . --export-html report.html --export-markdown summary.md
        deployguard scan local -p . --export-gitleaks gitleaks.json
        deployguard scan local -p . --compare-baseline baseline.json
    """
    click.echo(f"\n🔍 Scanning: {os.path.abspath(path)}")
    click.echo("=" * 60)
    
    # Determine patterns file
    if not patterns:
        default_patterns = Path(__file__).parent.parent.parent / "config" / "secret_patterns.yaml"
        if default_patterns.exists():
            patterns = str(default_patterns)
    
    try:
        scanner = SecretScanner(patterns_file=patterns)
        
        # Scan current files
        click.echo("\n📁 Scanning current files...")
        results = scanner.scan_directory(path)
        
        all_findings: List[Finding] = []
        for file_path, findings in results.items():
            all_findings.extend(findings)
        
        # Optionally scan git history
        history_findings = []
        if include_history:
            git_dir = Path(path) / ".git"
            if git_dir.exists():
                click.echo("\n📜 Scanning git history (this may take a while)...")
                cleaner = GitHistoryCleaner(scanner=scanner)
                history_secrets = cleaner.scan_git_history(path)
                history_findings = history_secrets
                click.echo(f"   Found {len(history_secrets)} unique secrets in git history")
        
        # Filter by severity
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order[min_severity]
        
        filtered_findings = [
            f for f in all_findings 
            if severity_order.get(f.severity.value if hasattr(f.severity, 'value') else str(f.severity), 0) >= min_level
        ]
        
        # Display summary
        click.echo("\n" + "=" * 60)
        click.echo("📊 SCAN SUMMARY")
        click.echo("=" * 60)
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in filtered_findings:
            sev_val = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            severity_counts[sev_val] = severity_counts.get(sev_val, 0) + 1
        
        click.echo(f"\n🔴 Critical: {severity_counts['critical']}")
        click.echo(f"🟠 High:     {severity_counts['high']}")
        click.echo(f"🟡 Medium:   {severity_counts['medium']}")
        click.echo(f"🟢 Low:      {severity_counts['low']}")
        click.echo(f"\n📝 Total findings: {len(filtered_findings)}")
        
        if history_findings:
            click.echo(f"📜 Unique secrets in history: {len(history_findings)}")
        
        # Count by type
        type_counts: Dict[str, int] = {}
        for f in filtered_findings:
            type_name = f.type.value if hasattr(f.type, 'value') else str(f.type)
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        if type_counts:
            click.echo("\n📋 By Type:")
            for type_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                click.echo(f"   • {type_name}: {count}")
        
        # Display detailed table
        format_finding_table(filtered_findings[:50])  # Limit display
        
        if len(filtered_findings) > 50:
            click.echo(f"\n... and {len(filtered_findings) - 50} more findings (use --output to export all)")
        
        # Interactive selection mode
        selected_findings = filtered_findings
        if interactive and filtered_findings:
            click.echo("\n" + "=" * 60)
            click.echo("🎯 INTERACTIVE SELECTION")
            click.echo("=" * 60)
            click.echo("Select which findings to include for masking/replacement.\n")
            
            selected_findings = []
            for i, finding in enumerate(filtered_findings, 1):
                var_name = finding.metadata.get("variable_name") or finding.suggested_variable or "-"
                value = finding.metadata.get("actual_value") or finding.exposed_value
                display_value = value[:30] + "..." if len(value) > 30 else value
                
                severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                sev_val = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                emoji = severity_emoji.get(sev_val, "⚪")
                
                type_val = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
                click.echo(f"{i}. {emoji} {type_val}")
                click.echo(f"   Variable: {var_name}")
                click.echo(f"   Value: {display_value}")
                click.echo(f"   File: {finding.file_path}:{finding.line_number}")
                
                if click.confirm("   Include this finding?", default=True):
                    selected_findings.append(finding)
                click.echo()
            
            click.echo(f"\n✅ Selected {len(selected_findings)} of {len(filtered_findings)} findings")
        
        # Export to files
        if output:
            ext = Path(output).suffix.lower()
            if ext == ".csv":
                export_findings_csv(selected_findings, output)
            else:
                export_findings_json(selected_findings, output, path)
            click.echo(f"\n📄 Findings exported to: {output}")
        
        if export_purge:
            export_findings_purge(selected_findings, export_purge, use_env_vars)
            click.echo(f"📄 Purge file exported to: {export_purge}")
        
        if export_env:
            export_env_template(selected_findings, export_env)
            click.echo(f"📄 Environment template exported to: {export_env}")
        
        if export_html:
            export_findings_html(selected_findings, export_html, os.path.abspath(path), show_values=show_values)
            click.echo(f"📄 HTML report exported to: {export_html}")
        
        # New report formats using ReportGenerator
        if export_markdown or export_gitleaks or export_bfg or export_detailed or compare_baseline:
            # Gather repository info
            repo_name = Path(path).name
            repo_info = RepositoryInfo(name=repo_name, path=os.path.abspath(path))
            
            # Try to get git info
            try:
                import subprocess
                git_dir = Path(path) / ".git"
                if git_dir.exists():
                    result = subprocess.run(
                        ["git", "-C", path, "rev-list", "--count", "HEAD"],
                        capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        repo_info.total_commits = int(result.stdout.strip())
                    
                    result = subprocess.run(
                        ["git", "-C", path, "branch", "-a", "--list"],
                        capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        repo_info.total_branches = len([b for b in result.stdout.strip().split('\n') if b])
            except Exception:
                pass
            
            report_gen = ReportGenerator(repo_info=repo_info)
            
            # Compare with baseline if provided
            if compare_baseline:
                click.echo(f"\n📊 Comparing with baseline: {compare_baseline}")
                baseline_findings = report_gen.load_baseline(compare_baseline)
                comparison = report_gen.compare_findings(baseline_findings, selected_findings)
                
                click.echo(f"   Baseline findings: {comparison['baseline_total']}")
                click.echo(f"   Current findings:  {comparison['current_total']}")
                click.echo(f"   Cleanup progress:  {comparison['cleanup_percentage']:.1f}%")
                click.echo(f"   Secrets cleaned:   {comparison['unique_cleaned']}")
                
                # Show severity comparison
                for sev, data in comparison['severity_comparison'].items():
                    if data['before'] > 0:
                        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                        click.echo(f"   {emoji} {sev.upper()}: {data['before']} → {data['after']} ({data['change']:+d})")
            
            if export_markdown:
                report_gen.export_markdown_report(selected_findings, export_markdown, language=language)
                click.echo(f"📄 Markdown report exported to: {export_markdown}")
            
            if export_gitleaks:
                report_gen.export_gitleaks_json(selected_findings, export_gitleaks)
                click.echo(f"📄 Gitleaks JSON exported to: {export_gitleaks}")
            
            if export_bfg:
                report_gen.export_bfg_purge_file(selected_findings, export_bfg, use_placeholders=True)
                click.echo(f"📄 BFG purge file exported to: {export_bfg}")
            
            if export_detailed:
                report_gen.export_detailed_report(selected_findings, export_detailed, include_values=show_values)
                click.echo(f"📄 Detailed report exported to: {export_detailed}")
        
        # Next steps guidance
        if filtered_findings:
            click.echo("\n" + "-" * 60)
            click.echo("NEXT STEPS:")
            click.echo("-" * 60)
            click.echo("1. Review the findings above")
            click.echo("2. Export to files for further processing:")
            click.echo(f"   deployguard scan local -p {path} --output findings.json --export-purge secrets.txt")
            click.echo("3. To clean git history:")
            click.echo("   git clone --mirror <repo_url> repo.git")
            click.echo("   deployguard clean history --path repo.git --execute")
        
        # Exit code based on findings
        if severity_counts["critical"] > 0:
            click.echo("\n⚠️  CRITICAL secrets found! Immediate action required.")
            raise SystemExit(2)
        elif severity_counts["high"] > 0:
            click.echo("\n⚠️  High severity secrets found. Review recommended.")
            raise SystemExit(1)
        else:
            click.echo("\n✅ Scan complete.")
            raise SystemExit(0)
            
    except SystemExit:
        raise
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        import traceback
        traceback.print_exc()
        raise SystemExit(3)


@scan.command("history")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to git repository"
)
@click.option(
    "--branch", "-b",
    help="Specific branch to scan (default: all branches)"
)
@click.option(
    "--all-branches/--single-branch",
    default=True,
    help="Scan all branches or just the specified one"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default="secrets_to_purge.txt",
    help="Output file for purge list (BFG-compatible format)"
)
@click.option(
    "--env-template", "-e",
    type=click.Path(),
    help="Generate .env.template file with suggested variable names"
)
@click.option(
    "--use-env-vars/--use-placeholder",
    default=False,
    help="Use environment variable placeholders instead of ***REMOVED***"
)
@click.option(
    "--export-markdown",
    type=click.Path(),
    help="Export Turkish/English markdown report"
)
@click.option(
    "--export-gitleaks",
    type=click.Path(),
    help="Export Gitleaks-compatible JSON"
)
@click.option(
    "--export-detailed",
    type=click.Path(),
    help="Export detailed project report"
)
@click.option(
    "--generate-reports",
    type=click.Path(),
    help="Generate all 5 Turkish-style audit reports to this directory"
)
@click.option(
    "--language",
    type=click.Choice(["tr", "en"]),
    default="tr",
    help="Report language (Turkish or English)"
)
@click.pass_context
def scan_history(ctx, path: str, branch: Optional[str], all_branches: bool,
                 output: str, env_template: Optional[str], use_env_vars: bool,
                 export_markdown: Optional[str], export_gitleaks: Optional[str],
                 export_detailed: Optional[str], generate_reports: Optional[str],
                 language: str):
    """
    Scan FULL git history for secrets across ALL commits and branches.
    
    This is the COMPREHENSIVE scan that:
    - Scans all commits (including deleted files in history)
    - Scans all branches
    - Generates Turkish-format security reports
    - Creates BFG-compatible purge files
    
    Like the Turkish security reports, this provides:
    - Total commit count and date range
    - All branches scanned
    - Secrets found in deleted files
    - Full cleanup roadmap
    
    Multi-Report Generation (--generate-reports):
    Generates 5 separate Turkish-style audit reports:
    1. Overview Report - Executive summary, repo metrics
    2. History Report - Commit/branch analysis
    3. Variables Report - Environment variable definitions
    4. Remediation Report - Cleanup instructions
    5. Summary Report - Project summary and next steps
    
    Examples:
        # Full history scan with Turkish report
        deployguard scan history --path /path/to/repo --export-markdown rapor.md
        
        # Generate all 5 Turkish-style reports
        deployguard scan history -p . --generate-reports ./reports/
        
        # Scan and generate all outputs
        deployguard scan history -p . -o secrets.txt --export-markdown report.md \\
            --export-gitleaks findings.json --export-detailed detailed.md
        
        # English report
        deployguard scan history -p ./repo --language en --export-markdown report.md
    """
    git_dir = Path(path) / ".git"
    is_bare = False
    if not git_dir.exists():
        # Check if it's a bare repo
        head_file = Path(path) / "HEAD"
        if not head_file.exists():
            click.echo(f"❌ Not a git repository: {path}", err=True)
            ctx.exit(1)
        is_bare = True
    
    click.echo(f"\n📜 FULL GIT HISTORY SCAN: {os.path.abspath(path)}")
    click.echo("=" * 60)
    
    # Gather repository info
    repo_name = Path(path).name
    repo_path = os.path.abspath(path)
    
    try:
        import subprocess
        
        # Get commit count
        total_commits = 0
        result = subprocess.run(
            ["git", "-C", path, "rev-list", "--all", "--count"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            total_commits = int(result.stdout.strip())
        
        # Get branch count
        total_branches = 0
        result = subprocess.run(
            ["git", "-C", path, "branch", "-a", "--list"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            branches = [b.strip() for b in result.stdout.strip().split('\n') if b.strip()]
            total_branches = len(branches)
        
        # Get date range
        first_commit_date = None
        last_commit_date = None
        
        result = subprocess.run(
            ["git", "-C", path, "log", "--all", "--reverse", "--format=%cs", "-1"],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            first_commit_date = result.stdout.strip()
        
        result = subprocess.run(
            ["git", "-C", path, "log", "--all", "--format=%cs", "-1"],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            last_commit_date = result.stdout.strip()
        
        # Get repo size
        size_bytes = 0
        git_path = Path(path) / ".git" if not is_bare else Path(path)
        if git_path.exists():
            for f in git_path.rglob("*"):
                if f.is_file():
                    try:
                        size_bytes += f.stat().st_size
                    except:
                        pass
        
        # Get remote URL
        remote_url = None
        result = subprocess.run(
            ["git", "-C", path, "remote", "get-url", "origin"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            remote_url = result.stdout.strip()
        
        # Calculate history years
        history_years = 0.0
        if first_commit_date and last_commit_date:
            from datetime import datetime
            try:
                first = datetime.strptime(first_commit_date, "%Y-%m-%d")
                last = datetime.strptime(last_commit_date, "%Y-%m-%d")
                history_years = (last - first).days / 365.25
            except:
                pass
        
        click.echo(f"📊 Repository: {repo_name}")
        click.echo(f"   Commits: {total_commits}")
        click.echo(f"   Branches: {total_branches}")
        if first_commit_date and last_commit_date:
            click.echo(f"   History: {first_commit_date} → {last_commit_date} ({history_years:.1f} years)")
        click.echo(f"   Size: {size_bytes / 1024 / 1024:.1f} MB")
        if remote_url:
            click.echo(f"   Remote: {remote_url}")
        
        if all_branches:
            click.echo(f"\n🔀 Scanning ALL {total_branches} branches...")
        elif branch:
            click.echo(f"\n🔀 Scanning branch: {branch}")
        
        cleaner = GitHistoryCleaner()
        
        click.echo(f"🔍 Scanning {total_commits} commits (this may take a while)...")
        
        secrets = cleaner.scan_git_history(
            repo_path=path,
            branch=branch,
            include_all_branches=all_branches,
        )
        
        if not secrets:
            click.echo("\n✅ No secrets found in git history!")
            ctx.exit(0)
        
        # Display findings
        click.echo(f"\n🔍 Found {len(secrets)} UNIQUE secrets across git history:")
        click.echo("-" * 60)
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for i, secret in enumerate(secrets[:20], 1):
            severity_counts[secret.severity] = severity_counts.get(secret.severity, 0) + 1
            
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡", 
                "low": "🟢"
            }
            emoji = severity_emoji.get(secret.severity, "⚪")
            
            # Truncate and mask secret value
            masked = secret.value[:10] + "..." + secret.value[-5:] if len(secret.value) > 20 else secret.value
            
            click.echo(f"\n{i}. {emoji} [{secret.severity.upper()}] {secret.secret_type}")
            click.echo(f"   🔑 Value: {masked}")
            click.echo(f"   📝 Suggested env var: DG_{secret.suggested_env_var}")
            click.echo(f"   📜 Found in {len(secret.commits)} commit(s)")
            click.echo(f"   📄 Files: {', '.join(secret.files[:3])}")
            if len(secret.files) > 3:
                click.echo(f"         +{len(secret.files) - 3} more files")
        
        if len(secrets) > 20:
            click.echo(f"\n... and {len(secrets) - 20} more secrets")
        
        # Count remaining severities
        for secret in secrets[20:]:
            severity_counts[secret.severity] = severity_counts.get(secret.severity, 0) + 1
        
        # Summary
        click.echo("\n" + "=" * 60)
        click.echo("📊 SCAN SUMMARY")
        click.echo("=" * 60)
        click.echo(f"🔴 Critical: {severity_counts['critical']}")
        click.echo(f"🟠 High:     {severity_counts['high']}")
        click.echo(f"🟡 Medium:   {severity_counts['medium']}")
        click.echo(f"🟢 Low:      {severity_counts['low']}")
        click.echo(f"\n📜 Total unique secrets: {len(secrets)}")
        click.echo(f"📁 Across {total_commits} commits in {total_branches} branches")
        
        # Generate purge file
        cleaner.generate_purge_file(secrets, output, use_env_vars)
        click.echo(f"\n📄 BFG purge file generated: {output}")
        
        # Generate env template if requested
        if env_template:
            cleaner.generate_env_template(secrets, env_template)
            click.echo(f"📄 Environment template generated: {env_template}")
        
        # Generate reports using ReportGenerator
        if export_markdown or export_gitleaks or export_detailed:
            # Convert SecretMatch to Finding for ReportGenerator
            findings = []
            for secret in secrets:
                finding = Finding(
                    type=secret.secret_type,
                    severity=secret.severity,
                    file_path=secret.files[0] if secret.files else "unknown",
                    line_number=0,
                    exposed_value=secret.value,
                    metadata={
                        "actual_value": secret.value,
                        "commits": secret.commits,
                        "files": secret.files,
                        "suggested_env_var": f"DG_{secret.suggested_env_var}",
                        "commit_count": len(secret.commits),
                        "file_count": len(secret.files),
                    }
                )
                findings.append(finding)
                
                # Add additional findings for each file
                for file_path in secret.files[1:]:
                    additional = Finding(
                        type=secret.secret_type,
                        severity=secret.severity,
                        file_path=file_path,
                        line_number=0,
                        exposed_value=secret.value,
                        metadata={
                            "actual_value": secret.value,
                            "commits": secret.commits,
                            "suggested_env_var": f"DG_{secret.suggested_env_var}",
                        }
                    )
                    findings.append(additional)
            
            repo_info = RepositoryInfo(
                name=repo_name,
                path=repo_path,
                total_commits=total_commits,
                total_branches=total_branches,
                history_years=history_years,
                size_bytes=size_bytes,
                first_commit_date=first_commit_date,
                last_commit_date=last_commit_date,
                remote_url=remote_url,
            )
            
            report_gen = ReportGenerator(repo_info=repo_info)
            
            if export_markdown:
                report_gen.export_markdown_report(findings, export_markdown, language=language)
                click.echo(f"📄 Markdown report ({language.upper()}) generated: {export_markdown}")
            
            if export_gitleaks:
                report_gen.export_gitleaks_json(findings, export_gitleaks)
                click.echo(f"📄 Gitleaks JSON generated: {export_gitleaks}")
            
            if export_detailed:
                report_gen.export_detailed_report(findings, export_detailed, include_values=False)
                click.echo(f"📄 Detailed report generated: {export_detailed}")
        
        # Generate all 5 Turkish-style audit reports
        if generate_reports:
            click.echo(f"\n📋 Generating 5 Turkish-style audit reports...")
            
            # Convert SecretMatch to Finding if not already done
            if not (export_markdown or export_gitleaks or export_detailed):
                findings = []
                for secret in secrets:
                    finding = Finding(
                        type=secret.secret_type,
                        severity=secret.severity,
                        file_path=secret.files[0] if secret.files else "unknown",
                        line_number=0,
                        exposed_value=secret.value,
                        metadata={
                            "actual_value": secret.value,
                            "commits": secret.commits,
                            "files": secret.files,
                            "suggested_env_var": f"DG_{secret.suggested_env_var}",
                            "commit_count": len(secret.commits),
                            "file_count": len(secret.files),
                        }
                    )
                    findings.append(finding)
                    
                    for file_path in secret.files[1:]:
                        additional = Finding(
                            type=secret.secret_type,
                            severity=secret.severity,
                            file_path=file_path,
                            line_number=0,
                            exposed_value=secret.value,
                            metadata={
                                "actual_value": secret.value,
                                "commits": secret.commits,
                                "suggested_env_var": f"DG_{secret.suggested_env_var}",
                            }
                        )
                        findings.append(additional)
            
            # Create MultiReportGenerator
            multi_gen = MultiReportGenerator(
                repo_path=path,
                output_dir=generate_reports,
                language=language
            )
            
            # Set findings
            multi_gen.set_findings(before=findings)
            
            # Generate all reports
            report_files = multi_gen.generate_all_reports()
            
            click.echo(f"\n✅ Generated {len(report_files)} reports:")
            for report_path in report_files:
                report_name = os.path.basename(report_path)
                click.echo(f"   📄 {report_name}")
        
        click.echo("\n" + "-" * 60)
        click.echo("NEXT STEPS:")
        click.echo("-" * 60)
        click.echo("1. Review the purge file and remove any false positives")
        click.echo("2. Create a mirror clone:")
        if remote_url:
            click.echo(f"   git clone --mirror {remote_url} {repo_name}.git")
        else:
            click.echo(f"   git clone --mirror <repo_url> {repo_name}.git")
        click.echo(f"3. Clean with DeployGuard:")
        click.echo(f"   deployguard clean history --path {repo_name}.git --execute")
        click.echo(f"4. Or use BFG Repo-Cleaner:")
        click.echo(f"   java -jar bfg.jar --replace-text {output} {repo_name}.git")
        click.echo("5. Push to new remote:")
        click.echo("   git push --mirror --force-with-lease <new_remote_url>")
        
        ctx.exit(0 if severity_counts["critical"] == 0 else 2)
        
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        import traceback
        traceback.print_exc()
        ctx.exit(3)


@scan.command("remote")
@click.option(
    "--repo", "-r",
    required=True,
    help="Repository in format owner/repo (GitHub) or project/repo (Bitbucket)"
)
@click.option(
    "--platform",
    type=click.Choice(["github", "bitbucket"]),
    default="github",
    help="Platform to use"
)
@click.option(
    "--branch", "-b",
    default="main",
    help="Branch to scan"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file for results (JSON format)"
)
@click.pass_context
def scan_remote(ctx, repo: str, platform: str, branch: str, output: Optional[str]):
    """
    Scan a remote repository for secrets.
    
    Requires authentication configured via 'deployguard auth'.
    
    Examples:
        deployguard scan remote --repo owner/repo
        deployguard scan remote -r myorg/myrepo --branch develop
    """
    from deployguard.utils.config import ConfigManager
    
    config = ConfigManager()
    
    click.echo(f"\n🔍 Scanning remote repository: {repo}")
    click.echo(f"📡 Platform: {platform}")
    click.echo(f"🔀 Branch: {branch}")
    click.echo("=" * 60)
    
    # Check for authentication
    if platform == "github":
        token = config.get("github_token")
        if not token:
            click.echo("❌ GitHub token not configured. Run: deployguard auth --github-token YOUR_TOKEN", err=True)
            ctx.exit(1)
    elif platform == "bitbucket":
        username = config.get("bitbucket_username")
        password = config.get("bitbucket_app_password")
        if not username or not password:
            click.echo("❌ Bitbucket credentials not configured. Run: deployguard auth --bitbucket", err=True)
            ctx.exit(1)
    
    try:
        # Import platform adapter
        if platform == "github":
            from deployguard.platforms.github_adapter import GitHubAdapter
            adapter = GitHubAdapter(token)
        else:
            from deployguard.platforms.bitbucket_adapter import BitbucketAdapter
            adapter = BitbucketAdapter(username, password)
        
        # Get repository content
        click.echo("\n📥 Fetching repository content...")
        
        owner, repo_name = repo.split("/")
        files = adapter.get_repository_files(owner, repo_name, branch)
        
        click.echo(f"   Found {len(files)} files to scan")
        
        # Scan files
        scanner = SecretScanner()
        all_findings = []
        
        with click.progressbar(files, label="🔍 Scanning files") as file_list:
            for file_info in file_list:
                content = adapter.get_file_content(owner, repo_name, file_info["path"], branch)
                if content:
                    findings = scanner.scan_file(file_info["path"], content)
                    all_findings.extend(findings)
        
        # Display results
        click.echo("\n" + "=" * 60)
        click.echo("📊 SCAN RESULTS")
        click.echo("=" * 60)
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in all_findings:
            sev_val = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            severity_counts[sev_val] = severity_counts.get(sev_val, 0) + 1
        
        click.echo(f"\n🔴 Critical: {severity_counts['critical']}")
        click.echo(f"🟠 High:     {severity_counts['high']}")
        click.echo(f"🟡 Medium:   {severity_counts['medium']}")
        click.echo(f"🟢 Low:      {severity_counts['low']}")
        click.echo(f"\n📝 Total findings: {len(all_findings)}")
        
        if all_findings:
            click.echo("\n⚠️  Secrets detected! For full history cleaning:")
            click.echo(f"   git clone --mirror https://github.com/{repo}.git repo.git")
            click.echo("   deployguard scan history --path repo.git")
        
        ctx.exit(0 if severity_counts["critical"] == 0 else 2)
        
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        ctx.exit(3)
