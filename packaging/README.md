# Release packaging

## Software bill of materials

Run from the source checkout used to build the signed RPMs. Use Python 3,
Syft (verified with 1.57.1), and libarchive's `bsdtar`. The system `tar`
on macOS is also supported.

```sh
python3 packaging/sbom.py dist/sbom path/to/edge-fwsec-*.rpm
```

The command produces one SPDX JSON document per RPM. It records the exact
RPM digest and scans the Go binaries extracted from that package so their
linked modules are included. `frontend-build.spdx.json` inventories the
declared frontend build inputs, including development dependencies.

Generate these files again from the final signed packages, then include
them in the signed release checksum manifest.
