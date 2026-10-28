"""Tests for the MITRE technique catalogue and the report generator.

Nothing here touches a real Sliver server or Ollama instance: the catalogue is
pure data, and report generation is exercised with an injected mock Ollama
client and a temporary output directory.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from adversary_sim import cli, reports, sliver, techniques
from adversary_sim.core import OllamaClient
from adversary_sim.safety import RiskLevel

# --- technique catalogue ---------------------------------------------------


def test_catalogue_contains_the_four_allowlisted_techniques():
    ids = {tech.id for tech in techniques.list_techniques()}
    assert ids == {"T1082", "T1083", "T1057", "T1016"}


def test_every_technique_command_is_on_the_sliver_allowlist():
    for tech in techniques.list_techniques():
        assert tech.command in sliver.DISCOVERY_COMMANDS


def test_every_technique_is_classified_state_changing():
    for tech in techniques.list_techniques():
        assert tech.risk == "state-changing"
    assert cli.RISK_BY_TOOL["sliver_run_discovery"] is RiskLevel.STATE_CHANGING


def test_technique_carries_metadata_and_detections():
    tech = techniques.get_technique("T1082")
    assert tech is not None
    assert tech.name == "System Information Discovery"
    assert tech.tactic == "Discovery"
    assert tech.description
    assert tech.detections  # at least one Sigma/auditd suggestion
    assert any("auditd" in d.lower() for d in tech.detections)
    assert any("sigma" in d.lower() for d in tech.detections)


@pytest.mark.parametrize("raw", ["T1082", "t1082", " attack.t1082 ", "attack.T1082"])
def test_get_technique_is_case_and_prefix_insensitive(raw):
    tech = techniques.get_technique(raw)
    assert tech is not None
    assert tech.id == "T1082"


def test_get_technique_returns_none_for_unknown():
    assert techniques.get_technique("T9999") is None
    assert techniques.get_technique("") is None


def test_resolve_technique_command_maps_to_sliver_command():
    assert techniques.resolve_technique_command("T1082") == "execute -o uname -a"
    assert techniques.resolve_technique_command("T1083") == "ls -la"
    assert techniques.resolve_technique_command("T1057") == "ps"
    assert techniques.resolve_technique_command("T1016") == "execute -o ip a"
    assert techniques.resolve_technique_command("T0000") is None


def test_generic_technique_keeps_agent_open():
    # An id outside the curated catalogue still yields a runnable technique.
    tech = techniques.technique_or_generic("T1033", name="System Owner/User Discovery")
    assert tech is not None
    assert tech.id == "T1033"
    assert tech.name == "System Owner/User Discovery"
    assert tech.command in sliver.DISCOVERY_COMMANDS
    assert tech.detections  # generic reports still carry curated detections


def test_generic_technique_defaults_and_validation():
    tech = techniques.technique_or_generic("t1053")
    assert tech is not None
    assert tech.id == "T1053"
    assert tech.command == techniques.DEFAULT_COMMAND_KEY
    with pytest.raises(ValueError):
        techniques.generic_technique("T1033", command_key="rm -rf /")


def test_technique_or_generic_curated_wins_and_rejects_junk():
    # Curated ids resolve to the curated entry, not a generic one.
    assert techniques.technique_or_generic("T1082") is techniques.get_technique("T1082")
    # Non-MITRE ids are rejected.
    assert techniques.technique_or_generic("not-a-technique") is None
    assert techniques.technique_or_generic("T123") is None


def test_as_dict_is_json_serialisable():
    payload = techniques.get_technique("T1057").as_dict()
    assert json.loads(json.dumps(payload))["id"] == "T1057"
    assert payload["risk"] == "state-changing"


# --- reports ---------------------------------------------------------------


def _mock_client(handler) -> OllamaClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://test")
    return OllamaClient(client=http)


def test_render_report_contains_all_sections(tmp_path):
    tech = techniques.get_technique("T1083")
    md = reports.render_report(
        tech,
        target="ab12cd34",
        evidence="total 8\n-rw-r--r-- canary_data.txt",
        operator="kadohack12",
        recommendations="### Sigma\n...",
        timestamp="20260101-000000",
        llm_used=True,
    )
    assert "# Purple Team Report — T1083" in md
    assert "| Opérateur | kadohack12 |" in md
    assert "| Cible | ab12cd34 |" in md
    assert "20260101-000000" in md
    assert "canary_data.txt" in md  # evidence
    assert "### Sigma" in md  # LLM recommendations
    assert "local LLM (Ollama)" in md
    assert "T1083" in md and "File and Directory Discovery" in md
    # The report shows the actual Sliver console command, not the bare Linux form.
    assert "**Commande Sliver** : `ls -la`" in md


def test_render_report_shows_sliver_console_syntax():
    tech = techniques.get_technique("T1082")
    md = reports.render_report(tech, target="s1", evidence="Linux", recommendations="x")
    assert "**Commande Sliver** : `execute -o uname -a`" in md


def test_render_report_falls_back_to_curated_detections():
    tech = techniques.get_technique("T1016")
    md = reports.render_report(tech, target="s1", evidence="eth0", recommendations="")
    assert "curated technique catalogue" in md
    assert tech.detections[0] in md


@pytest.mark.asyncio
async def test_generate_report_uses_llm_recommendations(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/chat"
        return httpx.Response(200, json={"message": {"content": "### Recommandations\n- Sigma X"}})

    client = _mock_client(handler)
    result = await reports.generate_report(
        techniques.get_technique("T1082"),
        target="ab12cd34",
        evidence="root",
        operator="tester",
        client=client,
        directory=tmp_path,
        now=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    )
    await client.aclose()

    assert result.llm_used is True
    assert result.path.name == "T1082_20260101-120000.md"
    assert result.path.parent == tmp_path
    body = result.path.read_text(encoding="utf-8")
    assert "### Recommandations" in body
    assert "root" in body


@pytest.mark.asyncio
async def test_generate_report_falls_back_when_llm_unreachable(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = _mock_client(handler)
    result = await reports.generate_report(
        techniques.get_technique("T1057"),
        target="s1",
        evidence="ps output",
        client=client,
        directory=tmp_path,
        now=datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC),
    )
    await client.aclose()

    assert result.llm_used is False
    assert result.llm_error  # the failure reason is preserved
    assert result.path.exists()
    assert "curated technique catalogue" in result.markdown


@pytest.mark.asyncio
async def test_generate_report_without_llm_skips_the_model(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("the model must not be contacted when use_llm=False")

    client = _mock_client(handler)
    result = await reports.generate_report(
        techniques.get_technique("T1082"),
        target="s1",
        evidence="root",
        client=client,
        directory=tmp_path,
        use_llm=False,
    )
    await client.aclose()

    assert result.llm_used is False
    assert result.path.exists()


def test_reports_dir_honours_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ADVERSARYSIM_REPORTS_DIR", str(tmp_path / "audits"))
    assert reports.reports_dir() == tmp_path / "audits"


def test_default_operator_honours_env(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_OPERATOR", "kadohack12")
    assert reports.default_operator() == "kadohack12"


def test_safe_fragment_sanitises_paths():
    assert reports._safe_fragment("T1082") == "T1082"
    assert reports._safe_fragment("../../etc/passwd") == "etc-passwd"
    assert reports._safe_fragment("") == "unknown"
