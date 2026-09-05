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

import os
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

#: Compiles and links, so a header without a usable library still fails.
_OPENSSL_PROBE = """
#include <openssl/evp.h>
int main(void) {
    unsigned char out[32];
    unsigned int len = 0;
    return EVP_Digest("x", 1, out, &len, EVP_sha256(), 0) == 1 ? 0 : 1;
}
"""


def openssl_usable() -> bool:
    """Whether this toolchain can compile and link against libcrypto.

    A wrong guess fails the whole extension build and drops the backend to the
    pure-Python parser, so this probes like a configure script instead of
    checking for a header.  MAILTRACE_OPENSSL=0 skips the probe; =1 makes an
    unusable OpenSSL a build error, which is what CI and the Docker image use.
    """
    setting = os.environ.get("MAILTRACE_OPENSSL", "").strip().lower()
    if setting in {"0", "false", "no", "off"}:
        return False
    required = setting in {"1", "true", "yes", "on"}

    import tempfile

    try:  # Python 3.12 dropped distutils from the stdlib; setuptools vendors it.
        from setuptools._distutils.ccompiler import new_compiler
    except ImportError:  # pragma: no cover - very old setuptools
        from distutils.ccompiler import new_compiler

    library = "libcrypto" if sys.platform == "win32" else "crypto"
    try:
        with tempfile.TemporaryDirectory() as work:
            source = Path(work) / "probe.c"
            source.write_text(_OPENSSL_PROBE, encoding="utf-8")
            compiler = new_compiler()
            objects = compiler.compile([str(source)], output_dir=work)
            compiler.link_executable(objects, str(Path(work) / "probe"), libraries=[library])
    except Exception as exc:  # noqa: BLE001 - any failure at all means "not usable"
        if required:
            raise SystemExit(
                "MAILTRACE_OPENSSL=1 was set, but OpenSSL could not be compiled and "
                f"linked against: {type(exc).__name__}: {exc}. Install the development "
                "headers (libssl-dev on Debian, `vcpkg install openssl` on Windows), "
                "or unset MAILTRACE_OPENSSL to fall back to the built-in SHA-256."
            ) from exc
        print(f"OpenSSL not usable ({type(exc).__name__}); SHA-256 will use the built-in implementation")
        return False
    print("OpenSSL found; SHA-256 will use EVP_Digest")
    return True


USE_OPENSSL = openssl_usable()

DEFINE_MACROS = [("MAILTRACE_ENGINE_VERSION", '"1.0.0"')]
LIBRARIES: list[str] = []
if USE_OPENSSL:
    DEFINE_MACROS.append(("MAILTRACE_USE_OPENSSL", "1"))
    LIBRARIES.append("libcrypto" if sys.platform == "win32" else "crypto")

SOURCES = [
    "src/sha256.cpp",
    "src/entropy.cpp",
    "src/parser.cpp",
    "src/bindings.cpp",
]

extension = Pybind11Extension(
    "mailtrace_engine",
    sources=sorted(str(HERE / name) for name in SOURCES),
    include_dirs=[str(HERE / "include")],
    cxx_std=20,
    define_macros=DEFINE_MACROS,
    libraries=LIBRARIES,
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
