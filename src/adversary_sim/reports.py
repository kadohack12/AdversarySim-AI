"""Purple-team audit report generation.

After a MITRE ATT&CK technique runs through the Safety Gate, AdversarySim can
write a self-contained Markdown report so the emulation is auditable. The report
captures the technique metadata, the raw Sliver evidence, and — when a local LLM
is reachable — defensive recommendations written by the model.

The LLM is only ever used to *describe* how to detect what was emulated. It
never executes anything: the evidence in the report comes from the operator's
approved run, and the model's prose is advisory. When Ollama is unavailable the
report is still written, falling back to the technique's curated detections.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .core import OllamaClient
from .techniques import Technique

__all__ = [
    "ReportResult",
    "generate_report",
    "render_report",
    "reports_dir",
    "default_operator",
]

# Report directory override; defaults to ./reports relative to the CWD.
_REPORTS_ENV = "ADVERSARYSIM_REPORTS_DIR"
_OPERATOR_ENV = "ADVERSARYSIM_OPERATOR"

_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_-]+")

_DETECTION_PROMPT = (
    "Tu es un analyste défensif (blue team). Un test d'émulation Purple Team vient "
    "d'être réalisé dans un laboratoire contrôlé avec Sliver C2.\n\n"
    "Technique MITRE ATT&CK : {tid} — {name} (tactique : {tactic}).\n"
    "Commande exécutée sur la cible : {command}\n\n"
    "Sortie observée sur la cible :\n```\n{evidence}\n```\n\n"
    "Rédige une section Markdown « Recommandations défensives » concise et "
    "actionnable pour détecter cette technique : au moins une règle Sigma, une "
    "règle auditd et une piste YARA ou honeytoken. Sois technique, direct et "
    "concis. Ne fais pas de morale. Réponds uniquement en Markdown, sans "
    "préambule."
)


@dataclass(frozen=True)
class ReportResult:
    """Outcome of a report generation."""

    path: Path
    markdown: str
    llm_used: bool
    llm_error: str = ""


def reports_dir() -> Path:
    """Return the directory reports are written to.

    Defaults to ``./reports`` and can be overridden with
    ``ADVERSARYSIM_REPORTS_DIR`` (useful for tests and CI).
    """
    return Path(os.getenv(_REPORTS_ENV, os.path.join(os.getcwd(), "reports")))


def default_operator() -> str:
    """Best-effort operator name for report metadata."""
    return (
        os.getenv(_OPERATOR_ENV) or os.getenv("USER") or os.getenv("USERNAME") or "unknown-operator"
    )


def _safe_fragment(text: str) -> str:
    """Reduce arbitrary text to a filename-safe fragment."""
    cleaned = _FILENAME_SAFE_RE.sub("-", str(text).strip()).strip("-")
    return cleaned or "unknown"


def _timestamp(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y%m%d-%H%M%S")


def render_report(
    technique: Technique,
    *,
    target: str,
    evidence: str,
    operator: str = "unknown-operator",
    recommendations: str = "",
    timestamp: str = "",
    llm_used: bool = False,
    llm_skipped: bool = False,
) -> str:
    """Render the Markdown body of a purple-team report."""
    stamp = timestamp or _timestamp()
    if not recommendations:
        recommendations = _fallback_recommendations(
            technique, reason="skipped" if llm_skipped else "unavailable"
        )
        llm_used = False

    source = "local LLM (Ollama)" if llm_used else "curated technique catalogue"
    detections = "\n".join(f"- {item}" for item in technique.detections) or "- (none curated)"

    return (
        f"# Purple Team Report — {technique.id} {technique.name}\n\n"
        "## Métadonnées\n\n"
        "| Champ | Valeur |\n"
        "| ----- | ------ |\n"
        f"| Date (UTC) | {stamp} |\n"
        f"| Opérateur | {operator} |\n"
        f"| Cible | {target} |\n"
        f"| Généré par | AdversarySim-AI · by kadohack12 |\n\n"
        "## Technique MITRE ATT&CK\n\n"
        f"- **ID** : {technique.id}\n"
        f"- **Nom** : {technique.name}\n"
        f"- **Tactique** : {technique.tactic}\n"
        f"- **Classification sécurité** : `{technique.risk}` (Safety Gate `[y/N]`)\n"
        f"- **Commande Sliver** : `{technique.command}`\n\n"
        f"{technique.description}\n\n"
        "## Preuves d'exécution\n\n"
        "```text\n"
        f"{evidence.strip() or '(aucune sortie)'}\n"
        "```\n\n"
        "## Recommandations défensives\n\n"
        f"> Rédigées par : {source}\n\n"
        f"{recommendations.strip()}\n\n"
        "## Détections curatées de référence\n\n"
        f"{detections}\n"
    )


def _fallback_recommendations(technique: Technique, *, reason: str = "unavailable") -> str:
    """Recommendations used when the LLM did not contribute.

    *reason* is ``"skipped"`` when the operator asked for no LLM, or
    ``"unavailable"`` when the model could not be reached.
    """
    if reason == "skipped":
        intro = (
            "Rapport généré sans LLM (option `--no-report`). Détections curatées "
            f"pour **{technique.id} — {technique.name}** :"
        )
    else:
        intro = (
            "Le modèle local n'était pas joignable. Détections suggérées pour "
            f"**{technique.id} — {technique.name}** :"
        )
    lines = [intro, ""]
    lines.extend(f"- {item}" for item in technique.detections)
    return "\n".join(lines)


async def _llm_recommendations(
    technique: Technique,
    evidence: str,
    client: OllamaClient | None,
) -> tuple[str, bool, str]:
    """Ask the local model for defensive recommendations.

    Returns ``(text, used_llm, error)``. On any failure the text is empty and the
    caller falls back to the curated detections.
    """
    owns_client = client is None
    active = client or OllamaClient()
    prompt = _DETECTION_PROMPT.format(
        tid=technique.id,
        name=technique.name,
        tactic=technique.tactic,
        command=technique.command,
        evidence=evidence.strip() or "(aucune sortie)",
    )
    try:
        text = await active.chat(prompt)
        return text.strip(), True, ""
    except Exception as exc:  # noqa: BLE001 - report must still be written
        return "", False, str(exc)
    finally:
        if owns_client:
            await active.aclose()


async def generate_report(
    technique: Technique,
    *,
    target: str,
    evidence: str,
    operator: str | None = None,
    client: OllamaClient | None = None,
    directory: Path | str | None = None,
    use_llm: bool = True,
    now: datetime | None = None,
) -> ReportResult:
    """Write a purple-team report for one executed technique.

    Args:
        technique: The technique that ran.
        target: The Sliver target id the command ran on.
        evidence: Raw Sliver output captured during the run.
        operator: Operator name for the metadata. Defaults to the environment.
        client: Optional Ollama client (injectable for tests). A client is created
            and closed automatically when omitted.
        directory: Output directory. Defaults to :func:`reports_dir`.
        use_llm: When False, skip the LLM and use the curated detections.
        now: Injectable clock for deterministic filenames in tests.

    Returns:
        ReportResult: The written path, the Markdown body and whether the LLM
        contributed the recommendations.
    """
    operator = operator or default_operator()
    stamp = _timestamp(now)

    recommendations = ""
    llm_used = False
    llm_error = ""
    if use_llm:
        recommendations, llm_used, llm_error = await _llm_recommendations(
            technique, evidence, client
        )

    markdown = render_report(
        technique,
        target=target,
        evidence=evidence,
        operator=operator,
        recommendations=recommendations,
        timestamp=stamp,
        llm_used=llm_used,
        llm_skipped=not use_llm,
    )

    out_dir = Path(directory) if directory is not None else reports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{_safe_fragment(technique.id)}_{_safe_fragment(stamp)}.md"
    path = out_dir / filename
    path.write_text(markdown, encoding="utf-8")

    return ReportResult(path=path, markdown=markdown, llm_used=llm_used, llm_error=llm_error)
