"""Tests for the public API surface.

These guard the metadata a downstream caller or packager reads: the exported
version, the stability classifier, and the names in ``__all__``. A release that
renames a symbol, bumps the version or changes its maturity claim should fail
here rather than in someone else's install.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest

import gromon_limiter
from gromon_limiter import AuthLimiter, ConfigurationError, Limiter, Policy
from gromon_limiter.policies import Rule, by_ip

# Resolved from this file so the suite also runs from an unpacked sdist, which
# ships pyproject.toml at the top level next to the package.
ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "gromon_limiter" / "__init__.py"


def _project_table() -> str:
    """Return the body of the ``[project]`` table.

    Parsed with a regex rather than ``tomllib`` because ``requires-python`` is
    ``>=3.10`` and ``tomllib`` only exists from 3.11; a test must not be the
    reason the oldest supported interpreter cannot run the suite.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r"^\[project\]$(.*?)(?=^\[)", text, re.MULTILINE | re.DOTALL)
    assert match is not None, "pyproject.toml has no [project] table"
    return match.group(1)


def _declared_version() -> str:
    match = re.search(r'^version = "([^"]+)"', _project_table(), re.MULTILINE)
    assert match is not None, "pyproject.toml declares no version"
    return match.group(1)


def test_declared_version_is_the_one_the_package_reports() -> None:
    """``__version__`` must agree with the version being released.

    It is read from the installed distribution's metadata rather than
    hardcoded, so this fails if a release is cut from a pyproject that the
    module does not reflect.

    The suite is also expected to run from an unpacked sdist in an environment
    where nothing was installed, which is how a distro packager reads it. That
    case is legitimate rather than a packaging fault, so it is compared against
    the fallback literal instead of being failed outright.
    """
    try:
        installed: str | None = version("gromon-limiter")
    except PackageNotFoundError:
        installed = None
    reported = gromon_limiter.__version__
    if installed is not None:
        assert reported == installed
    assert reported == _declared_version()


def test_uninstalled_fallback_matches_the_declared_version() -> None:
    """The literal used when no distribution is installed must not drift.

    It is the only copy of the version in the source tree, so it is the one
    place a release could bump the version and leave a stale string behind.
    """
    source = INIT.read_text(encoding="utf-8")
    match = re.search(r'^_FALLBACK_VERSION = "([^"]+)"', source, re.MULTILINE)
    assert match is not None, "__init__.py no longer defines _FALLBACK_VERSION"
    assert match.group(1) == _declared_version()


def test_classifier_agrees_with_the_released_major_version() -> None:
    """A 1.x release must not advertise itself as beta.

    Packagers gate on the classifier, so publishing ``4 - Beta`` beside a 1.0.0
    version tells downstream users something untrue about the release.
    """
    classifiers = re.findall(r'"(Development Status :: \d+[^"]*)"', _project_table())
    assert len(classifiers) == 1, f"expected one Development Status, got {classifiers}"
    expected = "5" if _declared_version().split(".")[0] != "0" else "4"
    assert classifiers[0].startswith(f"Development Status :: {expected} -")


def test_all_names_are_importable_and_unique() -> None:
    """Every advertised name exists exactly once.

    ``__all__`` is documented as the stable surface, so a typo or a leftover
    entry is a broken promise rather than a cosmetic issue.
    """
    assert len(gromon_limiter.__all__) == len(set(gromon_limiter.__all__))
    missing = [name for name in gromon_limiter.__all__ if not hasattr(gromon_limiter, name)]
    assert not missing, f"__all__ advertises missing names: {missing}"


def _policy() -> Policy:
    return Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))


@pytest.mark.parametrize("cls", [AuthLimiter, Limiter])
def test_flask_entry_points_reject_a_policy_in_the_app_slot(cls: type) -> None:
    """A Policy passed as the app is a mistake worth naming.

    ``Limiter(Policy(...))`` is the shape a caller reaches for first. Left
    unchecked the policy is accepted as the app and the error that surfaces is
    an ImportError about Flask, which points at installing a dependency the
    caller never wanted.
    """
    with pytest.raises(ConfigurationError, match="takes a Flask app as its first argument"):
        cls(_policy())  # type: ignore[arg-type]


def test_the_rejection_names_the_framework_free_engine() -> None:
    """The error has to say what to use instead, not only what went wrong."""
    with pytest.raises(ConfigurationError) as excinfo:
        Limiter(_policy())  # type: ignore[arg-type]
    message = str(excinfo.value)
    assert "LimiterCore" in message
    assert "Settings" in message
    assert "Identity" in message


def test_init_app_rejects_a_policy_too() -> None:
    """The deferred form is the same mistake and gets the same answer."""
    with pytest.raises(ConfigurationError, match="takes a Flask app as its first argument"):
        AuthLimiter().init_app(_policy())  # type: ignore[arg-type]


def test_policy_still_works_as_a_keyword_argument() -> None:
    """The guard must not catch the supported spelling.

    ``Limiter.for_policy`` passes the policy by keyword, so the check has to
    stay on the positional path only.
    """
    limiter = Limiter.for_policy(_policy())
    assert limiter.default_policy is not None
    assert limiter.default_policy.name == "api"
