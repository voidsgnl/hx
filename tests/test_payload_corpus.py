"""Validation tests for the file-backed payload corpus."""
import pytest

from hx.payload_loader import PAYLOAD_ROOT, PayloadSet, get_payload_set
from hx.payloads import Context


def test_every_engine_loads_and_validates():
    engine_dirs = [
        path for path in PAYLOAD_ROOT.iterdir()
        if path.is_dir()
    ]
    assert engine_dirs
    for engine_dir in engine_dirs:
        get_payload_set(engine_dir.name)


@pytest.mark.parametrize("context", list(Context))
def test_xss_covers_every_required_context(context):
    payload_set = get_payload_set("xss")
    required = payload_set.manifest.contexts.get(context.value)
    if not required:
        pytest.skip(f"{context.value} is optional or unsupported")
    entries = payload_set.payloads_for(context)
    assert entries
    for entry in entries:
        assert entry.text.strip()
        assert "\x00" not in entry.text


def test_xss_payloads_contain_marker_token():
    payload_set = get_payload_set("xss")
    for context in Context:
        for entry in payload_set.payloads_for(context):
            assert "{M}" in entry.text, f"{entry.path} has no {{M}} token"


@pytest.mark.parametrize("context", list(Context))
def test_payload_cap_is_respected(context):
    payload_set = get_payload_set("xss")
    assert (
        len(payload_set.ordered_payloads(context))
        <= payload_set.manifest.max_attempts_per_context
    )


def test_unknown_context_directory_fails(tmp_path):
    engine_root = tmp_path / "engine"
    (engine_root / "bogus").mkdir(parents=True)
    (engine_root / "manifest.toml").write_text(
        'name = "engine"\nmax_attempts_per_context = 8\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown context directory"):
        PayloadSet("engine", tmp_path)


def test_missing_required_context_fails(tmp_path):
    engine_root = tmp_path / "engine"
    engine_root.mkdir()
    (engine_root / "manifest.toml").write_text(
        'name = "engine"\n'
        "max_attempts_per_context = 8\n"
        "[contexts.html_body]\n"
        "required = true\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="required context"):
        PayloadSet("engine", tmp_path)


def test_ordered_payloads_apply_numeric_priority_and_cap(tmp_path):
    engine_root = tmp_path / "engine"
    context_dir = engine_root / "html_body"
    context_dir.mkdir(parents=True)
    (engine_root / "manifest.toml").write_text(
        'name = "engine"\n'
        "max_attempts_per_context = 2\n"
        "[contexts.html_body]\n"
        "required = true\n",
        encoding="utf-8",
    )
    for number in range(1, 5):
        (context_dir / f"{number:02}_payload.txt").write_text(
            f"<script>{'{M}'}</script>{number}",
            encoding="utf-8",
        )

    payload_set = PayloadSet("engine", tmp_path)
    ordered = payload_set.ordered_payloads(Context.HTML_BODY)
    assert len(ordered) == 2
    assert ordered[0].endswith("1")
    assert ordered[1].endswith("2")
