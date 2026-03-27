from __future__ import annotations

from agentgate.trust.owasp_mapping import OWASPMapping, get_owasp_coverage, owasp_coverage_summary

VALID_COVERAGE_LEVELS = {"full", "partial", "minimal", "none"}
VALID_OWASP_IDS = {
    "LLM01",
    "LLM02",
    "LLM03",
    "LLM04",
    "LLM05",
    "LLM06",
    "LLM07",
    "LLM08",
    "LLM09",
    "LLM10",
}


def test_get_owasp_coverage_returns_ten_items():
    coverage = get_owasp_coverage()
    assert len(coverage) == 10


def test_each_item_is_owasp_mapping_instance():
    for item in get_owasp_coverage():
        assert isinstance(item, OWASPMapping)


def test_each_item_has_valid_owasp_id():
    ids = {item.owasp_id for item in get_owasp_coverage()}
    assert ids == VALID_OWASP_IDS


def test_each_item_has_nonempty_name():
    for item in get_owasp_coverage():
        assert isinstance(item.name, str) and item.name.strip(), (
            f"{item.owasp_id} has empty name"
        )


def test_each_item_has_valid_coverage_level():
    for item in get_owasp_coverage():
        assert item.coverage_level in VALID_COVERAGE_LEVELS, (
            f"{item.owasp_id} has invalid coverage_level: {item.coverage_level!r}"
        )


def test_each_item_components_is_list_of_strings():
    for item in get_owasp_coverage():
        assert isinstance(item.components, list), f"{item.owasp_id} components not a list"
        for comp in item.components:
            assert isinstance(comp, str), f"{item.owasp_id} component not a string: {comp!r}"


def test_each_item_gaps_is_list_of_strings():
    for item in get_owasp_coverage():
        assert isinstance(item.gaps, list), f"{item.owasp_id} gaps not a list"
        for gap in item.gaps:
            assert isinstance(gap, str), f"{item.owasp_id} gap not a string: {gap!r}"


def test_no_duplicated_owasp_ids():
    ids = [item.owasp_id for item in get_owasp_coverage()]
    assert len(ids) == len(set(ids)), "Duplicate OWASP IDs found"


# Known-correct mappings based on actual component behaviour

def test_llm01_prompt_injection_maps_to_prompt_injection_detector():
    coverage = get_owasp_coverage()
    llm01 = next(item for item in coverage if item.owasp_id == "LLM01")
    assert "prompt_injection" in llm01.components
    assert llm01.coverage_level in {"full", "partial"}


def test_llm02_sensitive_information_maps_to_data_exfiltration():
    coverage = get_owasp_coverage()
    llm02 = next(item for item in coverage if item.owasp_id == "LLM02")
    assert "data_exfiltration" in llm02.components
    assert llm02.coverage_level in {"full", "partial"}


def test_llm03_supply_chain_maps_to_dependency_checks():
    coverage = get_owasp_coverage()
    llm03 = next(item for item in coverage if item.owasp_id == "LLM03")
    assert "static_dependency_risk" in llm03.components
    assert llm03.coverage_level in {"partial", "minimal"}


def test_llm06_excessive_agency_maps_to_tool_related_components():
    coverage = get_owasp_coverage()
    llm06 = next(item for item in coverage if item.owasp_id == "LLM06")
    tool_related = {
        "tool_misuse",
        "runtime_tool_audit",
        "tool_exerciser",
        "static_prompt_tool_inspection",
    }
    assert bool(set(llm06.components) & tool_related), (
        f"LLM06 should include at least one tool-related component, got: {llm06.components}"
    )


def test_llm07_system_prompt_leakage_maps_to_system_prompt_leak():
    coverage = get_owasp_coverage()
    llm07 = next(item for item in coverage if item.owasp_id == "LLM07")
    assert "system_prompt_leak" in llm07.components
    assert llm07.coverage_level in {"full", "partial"}


def test_llm09_misinformation_maps_to_hallucination():
    coverage = get_owasp_coverage()
    llm09 = next(item for item in coverage if item.owasp_id == "LLM09")
    assert "hallucination" in llm09.components


def test_none_categories_have_empty_components_or_gaps():
    """Categories with 'none' coverage should still have gap descriptions."""
    for item in get_owasp_coverage():
        if item.coverage_level == "none":
            assert item.gaps, (
                f"{item.owasp_id} has coverage_level 'none' but no gaps listed"
            )


# Summary tests

def test_owasp_coverage_summary_structure():
    summary = owasp_coverage_summary()
    assert isinstance(summary, dict)
    assert "covered_count" in summary
    assert "total" in summary
    assert "coverage_level" in summary
    assert "categories" in summary


def test_owasp_coverage_summary_total_is_ten():
    summary = owasp_coverage_summary()
    assert summary["total"] == 10


def test_owasp_coverage_summary_categories_length():
    summary = owasp_coverage_summary()
    assert len(summary["categories"]) == 10


def test_owasp_coverage_summary_covered_count_is_int():
    summary = owasp_coverage_summary()
    assert isinstance(summary["covered_count"], int)
    assert 0 <= summary["covered_count"] <= 10


def test_owasp_coverage_summary_covered_count_matches_full_and_partial():
    coverage = get_owasp_coverage()
    expected = sum(
        1 for item in coverage if item.coverage_level in {"full", "partial"}
    )
    summary = owasp_coverage_summary()
    assert summary["covered_count"] == expected


def test_owasp_coverage_summary_category_dicts_have_required_keys():
    summary = owasp_coverage_summary()
    required_keys = {"id", "name", "level", "components", "gaps"}
    for cat in summary["categories"]:
        assert required_keys <= set(cat.keys()), (
            f"Category dict missing keys: {required_keys - set(cat.keys())}"
        )


def test_owasp_coverage_summary_coverage_level_is_partial_or_full_or_minimal():
    summary = owasp_coverage_summary()
    assert summary["coverage_level"] in {"full", "partial", "minimal", "none"}
