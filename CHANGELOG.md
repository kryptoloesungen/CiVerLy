# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Nix flake for reproducible builds, development environments, AppImage and
  Docker image generation.
- GitHub Actions CI pipelines for running doctests.
- File-based Espresso minimizer workflow and new `MINIMIZER` option in
  `MODEL_OPTIONS`.
- Test vectors for HALFLOOP-24 and ABC ciphers.

### Changed

- Removed `complist` indirection from `Cipher`; modeling and report generation
  now operate directly on `self.nodes`.
- Simplified `_dfs_traversal()` to return only depths.
- Minor changes to LaTeX reports.
- Migrated build system from `setup.py` to pure `pyproject.toml`.
- Rewrote Makefile to provide test targets instead of C++ compilation.
- Simplified installation and documentation build docs to use Nix and pip.
- Replaced manual Dockerfile with Nix-based Docker image build.

### Removed

- `setup.py`, `MANIFEST.in`, `docker/Dockerfile`, `docs/Makefile`,
  `docs/build/`.

## [1.0.0] - Initial Release

Initial version as released by the BSI.
