"""Enforces invariants on the release/publish workflows.

This test is the regression net for the hardening introduced in the
'bulletproof release pipeline' PR. Each assertion catches a specific
class of supply-chain regression. The test runs without secrets or
network access — it inspects the workflow YAML files in the repo and
asserts file-shape invariants only.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

RELEASE_WORKFLOWS = [
    "publish_to_pypi.yml",
    "release-docker.yml",
    "create-release.yml",
    "_publish-container.yml",
]

SHA_PIN_RE = re.compile(r"@[0-9a-f]{40}\b")
USES_LINE_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)")


def _read_workflow_text(name: str) -> str:
    path = WORKFLOWS_DIR / name
    assert path.exists(), f"Expected workflow {name} to exist at {path}"
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("workflow", RELEASE_WORKFLOWS)
def test_release_workflows_only_use_sha_pinned_actions(workflow: str) -> None:
    """Every `uses:` in a release workflow must reference a 40-hex SHA, not a tag."""
    text = _read_workflow_text(workflow)
    offenders: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = USES_LINE_RE.match(line)
        if not m:
            continue
        ref = m.group(1)
        # Local reusable workflows (./.github/workflows/...) have no @ref
        if ref.startswith("./"):
            continue
        if "@" not in ref:
            offenders.append((lineno, line.rstrip()))
            continue
        if not SHA_PIN_RE.search(ref):
            offenders.append((lineno, line.rstrip()))
    assert not offenders, (
        f"{workflow} contains non-SHA-pinned action references:\n"
        + "\n".join(f"  L{n}: {ln}" for n, ln in offenders)
    )


def test_publish_pypi_has_explicit_attestations_true() -> None:
    """The PyPI publish step must explicitly set attestations: true."""
    text = _read_workflow_text("publish_to_pypi.yml")
    assert re.search(
        r"attestations:\s*true", text
    ), "publish_to_pypi.yml must set 'attestations: true' explicitly"


def test_publish_pypi_does_not_pass_password_to_pypi_publish() -> None:
    """No `password:` input is passed to pypa/gh-action-pypi-publish (OIDC only)."""
    text = _read_workflow_text("publish_to_pypi.yml")
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if "pypa/gh-action-pypi-publish" in line:
            window = "\n".join(lines[idx : idx + 30])
            assert "password:" not in window, (
                "Found `password:` near pypa/gh-action-pypi-publish in publish_to_pypi.yml — "
                "static credentials must not be passed; OIDC is mandatory"
            )


def test_publish_container_uses_keyless_cosign() -> None:
    """The cosign sign step must NOT pass --key (asserts keyless via Fulcio)."""
    text = _read_workflow_text("_publish-container.yml")
    cosign_sign_matches = re.findall(r"cosign sign[^\n]*", text)
    assert cosign_sign_matches, "_publish-container.yml must contain at least one `cosign sign` invocation"
    for invocation in cosign_sign_matches:
        assert "--key" not in invocation, (
            f"cosign sign invocation contains --key: {invocation!r}. "
            "Keyless signing (Fulcio + OIDC) is mandatory."
        )


def test_publish_container_login_steps_have_no_password() -> None:
    """No docker login step in _publish-container.yml passes a static password."""
    text = _read_workflow_text("_publish-container.yml")
    # Only acceptable usage of password: is `secrets.GITHUB_TOKEN` for GHCR.
    forbidden = re.findall(
        r"password:\s*\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)[A-Z_][A-Z0-9_]*\s*\}\}",
        text,
    )
    assert not forbidden, (
        f"_publish-container.yml passes static secrets as docker login passwords: {forbidden}. "
        "Only ${{ secrets.GITHUB_TOKEN }} (for GHCR auth) is permitted; Docker Hub must use OIDC."
    )


def test_cosign_pub_is_absent_from_repo_root() -> None:
    """The static cosign.pub key must not be present at repo root."""
    assert not (REPO_ROOT / "cosign.pub").exists(), (
        "cosign.pub exists at repo root. Keyless signing does not use a "
        "static public key — delete cosign.pub."
    )
