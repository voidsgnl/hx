import pytest

from hx.client import TargetClient
from hx.discover import FieldRole, classify_field, discover_forms
from hx.oracle import ORACLE_INIT_JS

BASE = "http://localhost:5000"


def test_classifies_csrf_fields_as_static():
    assert classify_field("csrf_token", "hidden") is FieldRole.STATIC
    assert classify_field("authenticity_token", "text") is FieldRole.STATIC
    assert classify_field(
        "__RequestVerificationToken", "hidden"
    ) is FieldRole.STATIC


def test_classifies_text_inputs_as_injectable():
    assert classify_field("q", "text") is FieldRole.INJECTABLE
    assert classify_field("search", "search") is FieldRole.INJECTABLE


def test_skips_disabled_buttons_and_file_fields():
    assert classify_field("query", "text", disabled=True) is FieldRole.SKIP
    assert classify_field("submit", "submit") is FieldRole.SKIP
    assert classify_field("upload", "file") is FieldRole.SKIP


@pytest.fixture
async def client():
    target = TargetClient(BASE, profile_dir="/tmp/hx-discover-profile")
    await target.start(oracle_init_script=ORACLE_INIT_JS)
    assert await target.warm()
    await target.page.goto(
        f"{BASE}/discovery", wait_until="domcontentloaded"
    )
    yield target
    await target.close()


async def test_discovers_eligible_forms_and_classifies_fields(client):
    forms = await discover_forms(client.page)

    assert len(forms) == 2
    assert {form.method for form in forms} == {"GET", "POST"}

    post_form = next(form for form in forms if form.method == "POST")
    fields = {item.name: item for item in post_form.fields}
    assert fields["csrf_token"].role is FieldRole.STATIC
    assert fields["q"].role is FieldRole.INJECTABLE
    assert post_form.action == f"{BASE}/post-csrf-check"
