"""Read-only discovery of HTML forms and their field metadata."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FieldRole(str, Enum):
    INJECTABLE = "injectable"
    STATIC = "static"
    SKIP = "skip"


CSRF_NAME_HINTS = (
    "csrf",
    "token",
    "authenticity",
    "_wpnonce",
    "nonce",
    "__requestverificationtoken",
)


@dataclass
class Field:
    name: str
    type: str
    role: FieldRole


@dataclass
class FormSpec:
    action: str
    method: str
    enctype: str
    fields: list[Field] = field(default_factory=list)


def classify_field(name: str, type_: str, disabled: bool = False) -> FieldRole:
    if disabled or not name:
        return FieldRole.SKIP

    field_type = (type_ or "text").lower()
    field_name = name.lower()

    if field_type in ("submit", "button", "reset", "image", "file"):
        return FieldRole.SKIP
    if field_type == "hidden" or any(hint in field_name for hint in CSRF_NAME_HINTS):
        return FieldRole.STATIC
    if field_type in (
        "text", "search", "url", "email", "tel", "password",
        "textarea", "number", "range", "",
    ):
        return FieldRole.INJECTABLE
    return FieldRole.STATIC


_JS_ENUMERATE = """
() => Array.from(document.forms).map(form => ({
  action: form.action,
  method: (form.method || 'GET').toUpperCase(),
  enctype: form.enctype || 'application/x-www-form-urlencoded',
  fields: Array.from(form.elements).map(element => ({
    name: element.name || '',
    type: (element.type || element.tagName || '').toLowerCase(),
    disabled: !!element.disabled
  }))
}))
"""


async def discover_forms(page) -> list[FormSpec]:
    """Return forms with at least one enabled, named, text-like field."""
    raw_forms = await page.evaluate(_JS_ENUMERATE)
    forms: list[FormSpec] = []
    for raw_form in raw_forms or []:
        fields = [
            Field(
                name=raw_field.get("name", ""),
                type=raw_field.get("type", ""),
                role=classify_field(
                    raw_field.get("name", ""),
                    raw_field.get("type", ""),
                    raw_field.get("disabled", False),
                ),
            )
            for raw_field in raw_form.get("fields", [])
        ]
        if not any(item.role is FieldRole.INJECTABLE for item in fields):
            continue
        forms.append(FormSpec(
            action=raw_form.get("action", ""),
            method=raw_form.get("method", "GET").upper(),
            enctype=raw_form.get(
                "enctype", "application/x-www-form-urlencoded"
            ),
            fields=fields,
        ))
    return forms
