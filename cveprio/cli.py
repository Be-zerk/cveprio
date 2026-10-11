"""Command-line interface.

    cveprio analyze CVE-2021-44228 [CVE...] [--inventory FILE] [--offline] [--llm PROVIDER] [--out DIR]
    cveprio demo                      # offline, fictional inventory, scripted AI example, dashboard
    cveprio dashboard out/report.json # (re)build the HTML dashboard
    cveprio serve out/                # view it at http://127.0.0.1:8765 (local only)
    cveprio evaluate [--llm PROVIDER] # evaluation report (fixtures + reference judgements)
    cveprio check-config              # show effective settings (secrets masked) and provider status
    cveprio capture-fixtures CVE...   # record live responses as offline fixtures

Exit codes: 0 ok · 1 runtime error · 2 invalid input · 3 completed but degraded (a source failed).
"""

from __future__ import annotations

import argparse
import functools
import http.server
import sys
from pathlib import Path

from pydantic import ValidationError

from cveprio import __version__
from cveprio.config import DEFAULT_FIXTURES, PROJECT_ROOT, Settings
from cveprio.llm.providers import ProviderError
from cveprio.models import Inventory, RunReport, SourceStatus
from cveprio.sources import InvalidCveId

EXAMPLE_INVENTORY = PROJECT_ROOT / "examples" / "inventory.json"


def _load_inventory(path: Path) -> Inventory:
    try:
        return Inventory.model_validate_json(path.read_text())
    except (OSError, ValidationError) as exc:
        raise SystemExit(f"error: cannot load inventory {path}: {exc}") from exc


def _summary(run: RunReport) -> None:
    for n in run.notices[:2]:
        print(f"! {n}")
    if run.discovery:
        disc = run.discovery
        print(f"\nDiscovery: {disc.total_found} candidate CVEs found, {len(disc.analyzed)} analysed"
              + (f", {len(disc.dropped)} over the cap (not analysed)" if disc.dropped else ""))
        for q in disc.queries:
            extra = f" (+{len(q.non_cve_ids)} non-CVE advisories)" if q.non_cve_ids else ""
            what = q.detail if q.status != "ok" else f"{len(q.cve_ids)} CVEs{extra}"
            print(f"  {q.asset_id:<18} {q.product[:22]:<22} {q.version[:24]:<24} {q.method:<9} {q.status:<15} {what}")
    print(f"\n{'CVE':<18} {'DECISION':<24} {'BASELINE':<9} {'EXPLOITATION':<20} {'SEVERITY':<9} EXPOSURE")
    for r in run.reports:
        d = r.decision
        label = d.label + ("*" if d.provisional else "")
        print(f"{r.cve_id:<18} {label:<24} {d.baseline_label:<9} {d.factors.get('exploitation', ''):<20} "
              f"{d.factors.get('severity', ''):<9} {d.factors.get('exposure', '')}")
    print("  * provisional: depends on context not supplied or not verifiable")
    degraded = [(r.cve_id, s) for r in run.reports for s in r.bundle.sources
                if s.status in (SourceStatus.FAILED, SourceStatus.RATE_LIMITED)]
    for cid, s in degraded:
        print(f"! DEGRADED {cid}: {s.source.value} {s.status.value} — {s.detail}")
    llm = {(r.llm.provider, r.llm.status.value) for r in run.reports}
    print("AI assessment: " + ", ".join(f"{p}={s}" for p, s in sorted(llm)))


def _degraded(run: RunReport) -> bool:
    return any(s.status in (SourceStatus.FAILED, SourceStatus.RATE_LIMITED) for r in run.reports for s in r.bundle.sources)


def cmd_analyze(args: argparse.Namespace, settings: Settings) -> int:
    from cveprio.dashboard import write_dashboard
    from cveprio.pipeline import make_runtime, run
    from cveprio.report import write_outputs

    inventory = _load_inventory(Path(args.inventory)) if args.inventory else None
    discover_cves = bool(getattr(args, "discover", False))
    ids = list(args.cve_ids) + (inventory.watchlist if inventory and not args.cve_ids and not discover_cves else [])
    if discover_cves and (inventory is None or args.offline):
        print("error: --discover needs --inventory and live sources (not --offline)", file=sys.stderr)
        return 2
    if not ids and not discover_cves:
        print("error: give at least one CVE ID, an inventory with a watchlist, or --inventory FILE --discover",
              file=sys.stderr)
        return 2
    try:
        rt = make_runtime(settings, offline=args.offline, provider_name=args.llm,
                          fixtures=Path(args.fixtures) if args.fixtures else DEFAULT_FIXTURES)
        if rt.provider_error:
            print(f"! AI provider not available — {rt.provider_error}. Continuing without AI assessment.")
        if discover_cves:
            print("Discovering CVEs from the inventory (NVD CPE match + OSV)...")
        result = run(ids, rt, inventory, discover_cves=discover_cves, max_cves=getattr(args, "max_cves", 150))
    except InvalidCveId as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ProviderError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = Path(args.out)
    paths = write_outputs(result, out)
    paths["dashboard"] = write_dashboard(result, out / "dashboard.html")
    _summary(result)
    print("\nWrote: " + ", ".join(str(p) for p in paths.values()))
    return 3 if _degraded(result) else 0


def cmd_demo(args: argparse.Namespace, settings: Settings) -> int:
    ns = argparse.Namespace(cve_ids=[], inventory=str(EXAMPLE_INVENTORY), offline=True,
                            llm=args.llm, out=args.out, fixtures=None)
    print("Running the OFFLINE DEMO: recorded fixtures + fictional inventory (no network, no API keys).")
    return cmd_analyze(ns, settings)


def cmd_dashboard(args: argparse.Namespace, settings: Settings) -> int:
    from cveprio.dashboard import write_dashboard

    run = RunReport.model_validate_json(Path(args.report).read_text())
    print(write_dashboard(run, Path(args.out)))
    return 0


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    directory = Path(args.directory).resolve()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    with http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler) as httpd:
        print(f"Serving {directory} at http://127.0.0.1:{args.port}/dashboard.html (local only; Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


def cmd_evaluate(args: argparse.Namespace, settings: Settings) -> int:
    from cveprio.evaluation import run_evaluation

    path = run_evaluation(settings, provider_name=args.llm, out_dir=Path(args.out))
    print(f"Wrote {path}")
    return 0


def cmd_check_config(args: argparse.Namespace, settings: Settings) -> int:
    from cveprio.llm.providers import make_provider

    print(f"cveprio {__version__}")
    print(settings)
    try:
        p = make_provider(settings)
        print(f"AI provider: {p.name} (model: {p.model})")
    except ProviderError as exc:
        print(f"AI provider: NOT AVAILABLE — {exc}")
    print("NVD API key: " + ("set (50 req/30 s)" if settings.nvd_api_key else "not set (5 req/30 s; slower)"))
    return 0


def cmd_capture(args: argparse.Namespace, settings: Settings) -> int:
    from cveprio.capture import capture
    from cveprio.net import SafeFetcher

    fetcher = SafeFetcher(min_interval_s={"services.nvd.nist.gov": 0.7 if settings.nvd_api_key else 6.5})
    print(capture(args.cve_ids, Path(args.out), fetcher, settings.nvd_api_key))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cveprio", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"cveprio {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze CVE IDs (optionally against an inventory)")
    a.add_argument("cve_ids", nargs="*")
    a.add_argument("--inventory", help="inventory JSON (see examples/inventory.json)")
    a.add_argument("--offline", action="store_true", help="use recorded fixtures (demo data) instead of live APIs")
    a.add_argument("--fixtures", help="fixture directory for --offline (default: fixtures/demo)")
    a.add_argument("--llm", choices=["none", "ollama", "openai_compatible", "anthropic", "scripted"],
                   help="override CVEPRIO_LLM_PROVIDER")
    a.add_argument("--discover", action="store_true",
                   help="find CVEs from the inventory's cpe/purl identifiers (live only) instead of its watchlist")
    a.add_argument("--max-cves", type=int, default=150, help="cap on discovered CVEs to analyse (default 150)")
    a.add_argument("--out", default="out/latest")
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("demo", help="offline demonstration with fictional inventory")
    d.add_argument("--llm", default="scripted", choices=["none", "scripted", "ollama", "openai_compatible", "anthropic"])
    d.add_argument("--out", default="out/demo")
    d.set_defaults(func=cmd_demo)

    db = sub.add_parser("dashboard", help="build dashboard HTML from a report.json")
    db.add_argument("report")
    db.add_argument("--out", default="out/latest/dashboard.html")
    db.set_defaults(func=cmd_dashboard)

    s = sub.add_parser("serve", help="serve an output directory on 127.0.0.1")
    s.add_argument("directory", nargs="?", default="out/demo")
    s.add_argument("--port", type=int, default=8765)
    s.set_defaults(func=cmd_serve)

    e = sub.add_parser("evaluate", help="run the evaluation set")
    e.add_argument("--llm", default="none", choices=["none", "ollama", "openai_compatible", "anthropic", "scripted"])
    e.add_argument("--out", default="evaluation/results")
    e.set_defaults(func=cmd_evaluate)

    c = sub.add_parser("check-config", help="show settings and provider status")
    c.set_defaults(func=cmd_check_config)

    cf = sub.add_parser("capture-fixtures", help="record live responses as offline fixtures")
    cf.add_argument("cve_ids", nargs="+")
    cf.add_argument("--out", default=str(DEFAULT_FIXTURES))
    cf.set_defaults(func=cmd_capture)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings.from_env()
    return int(args.func(args, settings))


if __name__ == "__main__":
    sys.exit(main())
