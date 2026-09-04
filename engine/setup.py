"""
Build the optional MailTrace C++20 parse engine as the Python extension module
``mailtrace_engine``.

This build is OPTIONAL in the strongest sense: nothing in the MailTrace install
path runs it, nothing in backend/requirements.txt refers to it, and the backend
starts, serves and analyses identically when the extension is absent.  See
engine/README.md.

Build-time requirements (deliberately NOT in backend/requirements.txt, because
they need a C++ compiler and the Render free tier has none):

    pip install pybind11>=2.11
    pip install ./engine          # or: cd engine && python setup.py build_ext --inplace

pyproject.toml declares pybind11 as a PEP 518 build dependency, so
``pip install ./engine`` fetches it into an isolated build environment without
adding anything to the runtime environment.
"""
from __future__ import annotations

import sys
from pathlib import Path

from setuptools import setup

HERE = Path(__file__).resolve().parent

try:
    from pybind11.setup_helpers import ParallelCompile, Pybind11Extension, build_ext
except ImportError:  # pragma: no cover - build-time only
    sys.exit(
        "pybind11 is required to build mailtrace_engine.\n"
        "    pip install pybind11>=2.11\n"
        "The MailTrace backend does not need this extension; the pure-Python "
        "parser is used automatically when it is missing."
    )

# Honour CPU count for the four translation units; harmless if unsupported.
ParallelCompile("MAILTRACE_BUILD_JOBS", default=0).install()

SOURCES = [
    "src/sha256.cpp",
    "src/entropy.cpp",
    "src/mime.cpp",
    "src/bindings.cpp",
]

extension = Pybind11Extension(
    "mailtrace_engine",
    sources=sorted(str(HERE / name) for name in SOURCES),
    include_dirs=[str(HERE / "include")],
    cxx_std=20,
    define_macros=[("MAILTRACE_ENGINE_VERSION", '"1.0.0"')],
)

# Warnings-as-information, not as errors: a build that fails on a pedantic
# warning would be worse than no extension at all, since the fallback is fine.
if sys.platform == "win32":
    extension.extra_compile_args += ["/W4", "/permissive-", "/EHsc"]
else:
    extension.extra_compile_args += ["-Wall", "-Wextra", "-O2", "-fvisibility=hidden"]

setup(
    name="mailtrace-engine",
    version="1.0.0",
    description="MailTrace C++20 MIME dissection, SHA-256 and Shannon entropy engine",
    long_description=(HERE / "README.md").read_text(encoding="utf-8") if (HERE / "README.md").is_file() else "",
    long_description_content_type="text/markdown",
    ext_modules=[extension],
    cmdclass={"build_ext": build_ext},
    python_requires=">=3.9",
    zip_safe=False,
)
