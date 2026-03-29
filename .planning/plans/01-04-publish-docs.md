# 01-04: Publish PyPI Package and Documentation

**Epic:** Core Scanner

## Goal

Make OpenAudit easy to install and use; create professional docs site.

## Acceptance Criteria

- Package `openaudit` on PyPI (testpypi first)
- `pip install openaudit` works
- README with badge: PyPI version, CI status
- Documentation site (MkDocs or Docusaurus) hosted on GitHub Pages
- Quickstart guide: install, scan, interpret report
- CONTRIBUTING.md with code style and test instructions

## Tasks

1. Prepare `pyproject.toml` with dependencies, entry points
2. Build and upload to TestPyPI; verify install in fresh venv
3. Write comprehensive README (features, install, usage)
4. Set up MkDocs; write pages: overview, tutorial, rules reference
5. Configure GitHub Actions to deploy docs on push to main
6. Publish to real PyPI
7. Announce on social/dev forums

## Dependencies

01-03

## Time Estimate

6 hours
