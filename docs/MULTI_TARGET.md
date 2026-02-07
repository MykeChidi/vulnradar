# Multi-Target Scanning

This document describes VulnRadar's multi-target scanning feature, configuration file formats, CLI flags, and recommended workflows for scanning many targets safely and efficiently.

## Overview

Multi-target scanning allows you to define multiple targets (websites or APIs) in a single YAML configuration file and run them either sequentially or concurrently. Each target can have its own options such as `timeout`, `retries`, and scanner-specific `options`.

## CLI Flags

- `--show-multi-config` : Generate a sample `multi_target_config.yaml` template in the current working directory and exit.
- `--targets-file <CONFIG_FILE>` : Path to a YAML configuration file that lists targets to scan.
- `--max-concurrent <N>` : Maximum concurrent target scans (default: `3`).
- `--sequential` : Run multi-target scans sequentially (no concurrency).

Generate a template:

```bash
python -m vulnradar --show-multi-config
```

Run a multi-target scan (concurrent):

```bash
python -m vulnradar --targets-file multi_target_config.yaml
```

Run sequentially:

```bash
python -m vulnradar --targets-file multi_target_config.yaml --sequential
```

## Configuration File Format

The generated template file is `multi_target_config.yaml`. VulnRadar supports the following formats in YAML/JSON (YAML recommended). The top-level shape may be:

1. A list of targets
2. An object with a `targets` key containing a list
3. An object mapping friendly names to a URL or to a dictionary with detailed settings

Examples:

- Simple list (string entries):

```yaml
- https://example.com
- https://api.example.com
```

- List with per-target dicts:

```yaml
- url: "https://example.com"
  name: "Example Site"
  timeout: 120
  retries: 2
  options:
    crawl_depth: 3
    timeout: 10
    max_workers: 5

- url: "https://api.example.com"
  name: "Example API"
  timeout: 180
  retries: 1
  options:
    crawl_depth: 2
    max_workers: 3
```


Notes on fields:

- `url` (required): Full URL including scheme (`http://` or `https://`).
- `name` (optional): Friendly display name for reports. Defaults to the URL if not provided.
- `timeout` (optional): Per-target timeout in seconds applied to the whole target scan. Default: `300` (5 minutes).
- `retries` (optional): Number of retry attempts on failure. Default: `0`.
- `options` (optional): Scanner options merged with global/default options passed via the CLI. These correspond to the same option keys used for single-target scans (e.g., `crawl_depth`, `max_workers`, `use_selenium`).

## Behavior & Outputs

- By default, multi-target scans run concurrently with `--max-concurrent` controlling the concurrency level.
- Use `--sequential` to run one target at a time (useful for fragile targets or hitting rate limits).
- The CLI will print a summary and save detailed outputs to the configured output directory (default `scan_results`). When running via the CLI, the tool saves:
  - `multi_target_summary.json` — aggregated summary of all targets
  - `multi_target_results/` — per-target JSON files (one file per target)

### Example run and output

```bash
python -m vulnradar --targets-file multi_target_config.yaml --max-concurrent 5
```

After the run completes, check:

```
scan_results/multi_target_summary.json
scan_results/multi_target_results/<target>_result.json
```

## Tips and Troubleshooting

- Start with `--sequential` and one or two targets to validate your configuration before scaling up.
- If targets are slow or unreliable, increase per-target `timeout` or add `retries`.
- Respect target owners and rate limits. Use `--sequential` or lower `--max-concurrent` when scanning third-party targets.
- The generated template contains recommended options and comments — use it as a starting point.

## Security & Authorization

Ensure you have permission to scan every target in your configuration file. Unauthorized scanning can be illegal and unethical. Keep the `multi_target_config.yaml` secure and avoid committing keys or credentials to version control.

---

For more examples and the template, run `python -m vulnradar --show-multi-config` and see the `multi_target_config.yaml` produced in your current directory.
