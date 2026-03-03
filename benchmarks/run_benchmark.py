"""
Benchmark Framework — CTO Audit Agent

Scarica repo pubbliche, esegue audit, confronta con issue GitHub.
Genera statistiche di detection rate per regola.

Uso:
    python benchmarks/run_benchmark.py [--skip-clone] [--skip-issues]
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

# Aggiungi src al path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.sources.local import LocalRepoSource


# ============================================================
# Configurazione repo da testare
# ============================================================

@dataclass
class RepoConfig:
    """Configurazione di una repo da benchmarkare."""
    name: str
    url: str
    language: str
    category: str  # "framework", "app", "library", "cli", "cms"
    expected_size: str  # "small", "medium", "large"
    # Parole chiave da cercare nelle issue per confronto
    issue_keywords: list[str] = field(default_factory=list)


REPOS: list[RepoConfig] = [
    # --- Python (5) ---
    RepoConfig(
        "httpie-cli", "https://github.com/httpie/cli.git",
        "python", "cli", "medium",
        ["CI", "test", "security", "docker", "dependency"],
    ),
    RepoConfig(
        "fastapi-users", "https://github.com/fastapi-users/fastapi-users.git",
        "python", "library", "small",
        ["security", "auth", "test", "CI"],
    ),
    RepoConfig(
        "black", "https://github.com/psf/black.git",
        "python", "cli", "medium",
        ["CI", "test", "type"],
    ),
    RepoConfig(
        "scrapy", "https://github.com/scrapy/scrapy.git",
        "python", "framework", "medium",
        ["security", "vulnerability", "test", "docker"],
    ),
    RepoConfig(
        "sanic", "https://github.com/sanic-org/sanic.git",
        "python", "framework", "medium",
        ["security", "CORS", "auth", "docker", "CI"],
    ),
    # --- JavaScript/TypeScript (4) ---
    RepoConfig(
        "express", "https://github.com/expressjs/express.git",
        "javascript", "framework", "medium",
        ["security", "vulnerability", "CORS", "headers"],
    ),
    RepoConfig(
        "fastify", "https://github.com/fastify/fastify.git",
        "javascript", "framework", "medium",
        ["security", "auth", "test", "CI"],
    ),
    RepoConfig(
        "ghost", "https://github.com/TryGhost/Ghost.git",
        "javascript", "cms", "large",
        ["security", "vulnerability", "docker", "CI", "auth"],
    ),
    RepoConfig(
        "socket.io", "https://github.com/socketio/socket.io.git",
        "typescript", "library", "small",
        ["security", "CORS", "auth", "vulnerability"],
    ),
    # --- Go (3) ---
    RepoConfig(
        "gin", "https://github.com/gin-gonic/gin.git",
        "go", "framework", "medium",
        ["security", "vulnerability", "test", "CI"],
    ),
    RepoConfig(
        "fiber", "https://github.com/gofiber/fiber.git",
        "go", "framework", "medium",
        ["security", "CORS", "auth", "docker"],
    ),
    RepoConfig(
        "minio", "https://github.com/minio/minio.git",
        "go", "app", "large",
        ["security", "vulnerability", "CVE", "docker", "auth"],
    ),
    # --- Java (2) ---
    RepoConfig(
        "spring-petclinic", "https://github.com/spring-projects/spring-petclinic.git",
        "java", "app", "small",
        ["security", "test", "docker", "CI"],
    ),
    RepoConfig(
        "java-design-patterns", "https://github.com/iluwatar/java-design-patterns.git",
        "java", "library", "large",
        ["test", "CI", "quality"],
    ),
    # --- Ruby (2) ---
    RepoConfig(
        "jekyll", "https://github.com/jekyll/jekyll.git",
        "ruby", "cli", "medium",
        ["security", "vulnerability", "test", "CI"],
    ),
    RepoConfig(
        "mastodon", "https://github.com/mastodon/mastodon.git",
        "ruby", "app", "large",
        ["security", "vulnerability", "CVE", "docker", "auth", "CORS"],
    ),
    # --- Rust (1) ---
    RepoConfig(
        "ripgrep", "https://github.com/BurntSushi/ripgrep.git",
        "rust", "cli", "medium",
        ["test", "CI", "security"],
    ),
    # --- PHP (1) ---
    RepoConfig(
        "laravel", "https://github.com/laravel/laravel.git",
        "php", "framework", "small",
        ["security", "auth", "CORS", "docker", "CI"],
    ),
    # --- C# (1) ---
    RepoConfig(
        "clean-architecture", "https://github.com/jasontaylordev/CleanArchitecture.git",
        "csharp", "app", "small",
        ["test", "CI", "docker", "security"],
    ),
    # --- C (1) ---
    RepoConfig(
        "redis", "https://github.com/redis/redis.git",
        "c", "app", "large",
        ["security", "vulnerability", "CVE", "test"],
    ),
]


# ============================================================
# Clone repos
# ============================================================

def clone_repos(repos_dir: Path) -> dict[str, Path]:
    """Clona le repo con --depth 1. Restituisce {name: path}."""
    paths = {}
    for repo in REPOS:
        dest = repos_dir / repo.name
        if dest.exists():
            print(f"  [skip] {repo.name} (gia presente)")
            paths[repo.name] = dest
            continue

        print(f"  [clone] {repo.name} ...")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", repo.url, str(dest)],
                capture_output=True, timeout=120, check=True,
            )
            paths[repo.name] = dest
            print(f"    OK")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"    ERRORE: {e}")

    return paths


# ============================================================
# Fetch GitHub issues
# ============================================================

def fetch_relevant_issues(repo_url: str, keywords: list[str], max_issues: int = 30) -> list[dict]:
    """Cerca issue rilevanti via GitHub API (senza autenticazione)."""
    # Estrai owner/repo dall'URL
    parts = repo_url.rstrip(".git").rstrip("/").split("/")
    owner, name = parts[-2], parts[-1]

    issues = []
    for kw in keywords[:3]:  # Limita a 3 keyword per evitare rate limit
        url = f"https://api.github.com/search/issues?q=repo:{owner}/{name}+{kw}+is:issue&per_page=10&sort=created&order=desc"
        try:
            resp = httpx.get(url, timeout=10, headers={"Accept": "application/vnd.github.v3+json"})
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", []):
                    issues.append({
                        "title": item["title"],
                        "url": item["html_url"],
                        "labels": [l["name"] for l in item.get("labels", [])],
                        "state": item["state"],
                        "keyword": kw,
                    })
            elif resp.status_code == 403:
                print(f"    [rate-limit] GitHub API rate limit raggiunto, pausa...")
                time.sleep(30)
        except httpx.TimeoutException:
            pass

        time.sleep(1)  # Rate limiting gentile

    # Deduplica per URL
    seen = set()
    unique = []
    for issue in issues:
        if issue["url"] not in seen:
            seen.add(issue["url"])
            unique.append(issue)

    return unique[:max_issues]


# ============================================================
# Run audit
# ============================================================

def run_audit(repo_path: Path) -> dict | None:
    """Esegue audit su una repo. Restituisce risultato serializzato."""
    try:
        source = LocalRepoSource(repo_path)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=repo_path,
            offline=True,
            auto_approve=True,
            no_llm=True,
        )
        result = orchestrator.run()

        # Raccogliere tutti i finding da tutti i layer
        all_findings = []
        layer_scores_dict = {}
        for layer_name, layer_score in result.health_score.layer_scores.items():
            layer_scores_dict[layer_name] = round(layer_score.score, 2)
            for f in layer_score.findings:
                all_findings.append({
                    "rule_id": f.rule_id,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "description": f.description[:200],
                    "layer": layer_name,
                })

        all_rule_ids = list(set(f["rule_id"] for f in all_findings))

        return {
            "health_score": round(result.health_score.overall_score, 2),
            "layer_scores": layer_scores_dict,
            "findings_count": len(all_findings),
            "findings": all_findings,
            "rule_ids": all_rule_ids,
        }
    except Exception as e:
        print(f"    ERRORE audit: {e}")
        return None


# ============================================================
# Analisi e confronto
# ============================================================

ISSUE_TO_RULE_MAP = {
    # Keyword nelle issue -> regole che dovrebbero scattare
    "no CI": ["INFRA-CICD-001"],
    "no tests": ["ARCH-TEST-001"],
    "no docker": ["INFRA-DOCKER-001"],
    "vulnerability": ["SEC-DEPS-001", "SEC-DEPS-CVE-001"],
    "CVE": ["SEC-DEPS-001", "SEC-DEPS-CVE-001"],
    "secret": ["SEC-SECRETS-CODE-001", "INFRA-CONFIG-001", "INFRA-CONFIG-002"],
    "SQL injection": ["SEC-SQL-001"],
    "CORS": ["SEC-CORS-001"],
    "auth": ["SEC-AUTH-001"],
    "hardcoded": ["SEC-SECRETS-CODE-001"],
    ".env": ["INFRA-CONFIG-001"],
}


def analyze_results(all_results: dict) -> dict:
    """Genera statistiche aggregate."""
    scores = []
    rule_freq = {}
    lang_scores = {}

    for name, data in all_results.items():
        if not data or "audit" not in data or data["audit"] is None:
            continue

        audit = data["audit"]
        score = audit["health_score"]
        scores.append(score)

        lang = data["config"]["language"]
        if lang not in lang_scores:
            lang_scores[lang] = []
        lang_scores[lang].append(score)

        for rule_id in audit["rule_ids"]:
            rule_freq[rule_id] = rule_freq.get(rule_id, 0) + 1

    total = len(scores)
    if total == 0:
        return {"error": "Nessun risultato valido"}

    return {
        "total_repos": total,
        "score_stats": {
            "mean": round(sum(scores) / total, 1),
            "median": round(sorted(scores)[total // 2], 1),
            "min": round(min(scores), 1),
            "max": round(max(scores), 1),
            "std": round((sum((s - sum(scores)/total)**2 for s in scores) / total)**0.5, 1),
        },
        "score_distribution": {
            "excellent_90_100": sum(1 for s in scores if s >= 90),
            "good_75_89": sum(1 for s in scores if 75 <= s < 90),
            "adequate_60_74": sum(1 for s in scores if 60 <= s < 75),
            "insufficient_40_59": sum(1 for s in scores if 40 <= s < 60),
            "critical_0_39": sum(1 for s in scores if s < 40),
        },
        "rule_frequency": dict(sorted(rule_freq.items(), key=lambda x: -x[1])),
        "rule_detection_rate": {
            rule: round(count / total * 100, 1)
            for rule, count in sorted(rule_freq.items(), key=lambda x: -x[1])
        },
        "language_scores": {
            lang: round(sum(s) / len(s), 1)
            for lang, s in sorted(lang_scores.items())
        },
    }


# ============================================================
# Main
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Benchmark CTO Audit Agent")
    parser.add_argument("--skip-clone", action="store_true", help="Salta il clone delle repo")
    parser.add_argument("--skip-issues", action="store_true", help="Salta il fetch delle issue")
    args = parser.parse_args()

    base_dir = Path(__file__).parent
    repos_dir = base_dir / "repos"
    results_dir = base_dir / "results"
    repos_dir.mkdir(exist_ok=True)
    results_dir.mkdir(exist_ok=True)

    all_results = {}

    # 1. Clone repos
    if not args.skip_clone:
        print("\n=== FASE 1: Clone repos ===")
        repo_paths = clone_repos(repos_dir)
    else:
        print("\n=== FASE 1: Skip clone (uso repos esistenti) ===")
        repo_paths = {r.name: repos_dir / r.name for r in REPOS if (repos_dir / r.name).exists()}

    print(f"\nRepo disponibili: {len(repo_paths)}")

    # 2. Run audit su ogni repo
    print("\n=== FASE 2: Audit ===")
    for repo in REPOS:
        if repo.name not in repo_paths:
            continue

        path = repo_paths[repo.name]
        print(f"\n  [{repo.name}] Auditing {path}...")
        start = time.time()
        audit = run_audit(path)
        elapsed = time.time() - start

        all_results[repo.name] = {
            "config": {
                "language": repo.language,
                "category": repo.category,
                "expected_size": repo.expected_size,
            },
            "audit": audit,
            "elapsed_seconds": round(elapsed, 1),
        }

        if audit:
            print(f"    Score: {audit['health_score']}/100 ({audit['findings_count']} findings) [{elapsed:.1f}s]")
        else:
            print(f"    FALLITO [{elapsed:.1f}s]")

    # 3. Fetch issues (opzionale)
    if not args.skip_issues:
        print("\n=== FASE 3: Fetch GitHub issues ===")
        for repo in REPOS:
            if repo.name not in all_results:
                continue
            print(f"  [{repo.name}] Cercando issue...")
            issues = fetch_relevant_issues(repo.url, repo.issue_keywords)
            all_results[repo.name]["issues"] = issues
            print(f"    {len(issues)} issue trovate")
    else:
        print("\n=== FASE 3: Skip issues ===")

    # 4. Analisi
    print("\n=== FASE 4: Analisi ===")
    stats = analyze_results(all_results)

    # 5. Salva risultati
    output_file = results_dir / "benchmark_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "repos": all_results,
            "statistics": stats,
        }, f, indent=2, ensure_ascii=False)

    print(f"\nRisultati salvati in {output_file}")

    # 6. Stampa riepilogo
    print("\n" + "=" * 60)
    print("RIEPILOGO BENCHMARK")
    print("=" * 60)
    print(f"\nRepo testate: {stats.get('total_repos', 0)}")
    if "score_stats" in stats:
        ss = stats["score_stats"]
        print(f"Score medio: {ss['mean']}/100 (mediana: {ss['median']}, min: {ss['min']}, max: {ss['max']})")

    if "score_distribution" in stats:
        print("\nDistribuzione:")
        for label, count in stats["score_distribution"].items():
            pct = round(count / stats["total_repos"] * 100)
            bar = "#" * (pct // 2)
            print(f"  {label:25s}: {count:2d} ({pct:3d}%) {bar}")

    if "rule_detection_rate" in stats:
        print("\nRegole piu frequenti (detection rate):")
        for rule, rate in list(stats["rule_detection_rate"].items())[:15]:
            print(f"  {rule:25s}: {rate:5.1f}%")

    if "language_scores" in stats:
        print("\nScore medio per linguaggio:")
        for lang, score in stats["language_scores"].items():
            print(f"  {lang:15s}: {score}/100")

    # 7. Genera report markdown
    report_file = results_dir / "benchmark_report.md"
    _generate_report(report_file, all_results, stats)
    print(f"\nReport: {report_file}")


def _generate_report(path: Path, results: dict, stats: dict) -> None:
    """Genera report markdown con risultati benchmark."""
    lines = [
        "# Benchmark CTO Audit Agent",
        "",
        f"Data: {time.strftime('%Y-%m-%d %H:%M')}",
        f"Repo testate: {stats.get('total_repos', 0)}",
        "",
        "## Risultati per repo",
        "",
        "| # | Repo | Language | Score | Findings | Tempo | Top Issues |",
        "|---|------|----------|-------|----------|-------|-----------|",
    ]

    i = 0
    for name, data in results.items():
        if not data or "audit" not in data or data["audit"] is None:
            continue
        i += 1
        audit = data["audit"]
        top_rules = ", ".join(audit["rule_ids"][:5])
        lines.append(
            f"| {i} | {name} | {data['config']['language']} | "
            f"{audit['health_score']} | {audit['findings_count']} | "
            f"{data['elapsed_seconds']}s | {top_rules} |"
        )

    if "score_stats" in stats:
        ss = stats["score_stats"]
        lines.extend([
            "",
            "## Statistiche",
            "",
            f"- **Media**: {ss['mean']}/100",
            f"- **Mediana**: {ss['median']}/100",
            f"- **Min**: {ss['min']}/100",
            f"- **Max**: {ss['max']}/100",
            f"- **Deviazione standard**: {ss['std']}",
        ])

    if "rule_detection_rate" in stats:
        lines.extend([
            "",
            "## Detection Rate per Regola",
            "",
            "| Regola | Detection Rate | Count |",
            "|--------|---------------|-------|",
        ])
        for rule, rate in stats["rule_detection_rate"].items():
            count = stats["rule_frequency"][rule]
            lines.append(f"| {rule} | {rate}% | {count}/{stats['total_repos']} |")

    if "language_scores" in stats:
        lines.extend([
            "",
            "## Score per Linguaggio",
            "",
            "| Linguaggio | Score Medio |",
            "|-----------|-------------|",
        ])
        for lang, score in stats["language_scores"].items():
            lines.append(f"| {lang} | {score}/100 |")

    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
