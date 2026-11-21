#!/usr/bin/env python3
"""Generate release SBOMs from Edge FWSec RPMs and the frontend lockfile."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def scan(source, destination, name, expected, version="", frontend=False):
    command = ["syft", "scan", "dir:.", "--source-name", name, "-o", f"spdx-json={destination}"]
    if version:
        command.extend(["--source-version", version])
    environment = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false")
    if frontend:
        environment["SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES"] = "true"
    subprocess.run(command, cwd=source, env=environment, check=True)
    report = json.loads(destination.read_text(encoding="utf-8"))
    packages = {package["name"] for package in report["packages"]}
    missing = expected - packages
    if missing:
        raise SystemExit(f"{name}: packages missing from scan: {', '.join(sorted(missing))}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="directory for the SPDX JSON files")
    parser.add_argument("rpms", metavar="RPM", type=Path, nargs="+")
    args = parser.parse_args()
    rpms = [rpm.resolve() for rpm in args.rpms]
    if len({rpm.name for rpm in rpms}) != len(rpms):
        parser.error("RPM filenames must be unique")
    for rpm in rpms:
        if not rpm.is_file() or not rpm.match("edge-fwsec-*.rpm"):
            parser.error(f"expected an Edge FWSec RPM: {rpm}")

    if not shutil.which("syft"):
        parser.error("syft is required")
    bsdtar = shutil.which("bsdtar")
    if not bsdtar and shutil.which("tar"):
        version = subprocess.check_output(["tar", "--version"], text=True)
        if "bsdtar" in version:
            bsdtar = "tar"
    if not bsdtar:
        parser.error("bsdtar (libarchive) is required to read the RPM payload")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    frontend_path = Path(__file__).resolve().parents[1] / "ui"
    with tempfile.TemporaryDirectory(prefix=".sbom-", dir=output) as scratch:
        staging = Path(scratch)
        reports = staging / "reports"
        reports.mkdir()
        for rpm in rpms:
            source = staging / rpm.stem
            source.mkdir()
            shutil.copyfile(rpm, source / rpm.name)
            for binary in ("efw-agent", "efw-web", "efwctl"):
                with (source / binary).open("wb") as payload:
                    subprocess.run(
                        [bsdtar, "-xOf", rpm, f"./usr/bin/{binary}"],
                        stdout=payload,
                        check=True,
                    )
            sha256 = hashlib.sha256(rpm.read_bytes()).hexdigest()
            scan(
                source,
                reports / f"{rpm.name}.spdx.json",
                rpm.name,
                {"edge-fwsec", "stdlib"},
                version=f"sha256:{sha256}",
            )
        frontend = staging / "frontend"
        frontend.mkdir()
        for name in ("package.json", "package-lock.json"):
            shutil.copyfile(frontend_path / name, frontend / name)
        scan(
            frontend,
            reports / "frontend-build.spdx.json",
            "edge-fwsec-frontend-build-inputs",
            {"svelte", "vite"},
            frontend=True,
        )
        for report in sorted(reports.iterdir()):
            report.replace(output / report.name)


if __name__ == "__main__":
    main()
