# Retrohunt Analyzer Service Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After `hugin.py` exports retrohunt results to CSV, if `RETROHUNT_ANALYZER_URL` is set in `munin.ini`, automatically POST the CSV to the internal retrohunt-analyzer-service and save the resulting HTML report and (optionally) enriched CSV alongside the original CSV — giving the user 2 or 3 output files depending on whether the service's Valhalla enrichment is configured.

**Architecture:** Add a single `RETROHUNT_ANALYZER_URL` config key to `munin.ini` (sentinel `-` means disabled). In `hugin.py`, after the CSV write loop, call a new `send_to_analyzer(csv_path, url)` function that POSTs the CSV to `POST {url}/api/v1/reports`, receives a ZIP response, and writes the contained HTML (and optional enriched CSV) to the same directory as the original CSV. Errors from the service print a warning but never abort the retrohunt run.

**Tech Stack:** Python 3, `requests` (already in requirements.txt), `zipfile` (stdlib), `configparser` (stdlib), `io` (stdlib) — no new dependencies.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `munin.ini` | Modify | Add `RETROHUNT_ANALYZER_URL = -` to `[DEFAULT]` |
| `hugin.py` | Modify | Read new config key; add `send_to_analyzer()`; call it after CSV loop |
| `tests/test_hugin_analyzer.py` | Create | Unit tests for `send_to_analyzer()` using `unittest.mock` |

---

## Task 1: Create the feature branch

**Files:**
- (git only, no file changes)

- [ ] **Step 1: Create and switch to the feature branch**

```bash
git checkout -b feature/retrohunt-analyzer-integration
```

Expected: `Switched to a new branch 'feature/retrohunt-analyzer-integration'`

- [ ] **Step 2: Verify you are on the right branch**

```bash
git branch --show-current
```

Expected: `feature/retrohunt-analyzer-integration`

---

## Task 2: Add `RETROHUNT_ANALYZER_URL` to the config template

**Files:**
- Modify: `munin.ini`

- [ ] **Step 1: Open `munin.ini` and add the new key**

In the `[DEFAULT]` section, after the `PROXY = -` line, add:

```ini
# URL of the internal retrohunt-analyzer-service (POST /api/v1/reports)
# Leave as - to disable. Example: http://retrohunt-analyzer.internal:8000
RETROHUNT_ANALYZER_URL = -
```

Result after edit — `munin.ini` `[DEFAULT]` block should look like:

```ini
[DEFAULT]

VT_PUBLIC_API_KEY = - # Found at https://www.virustotal.com/gui/my-apikey

MAL_SHARE_API_KEY = -
PAYLOAD_SEC_API_KEY = -
VALHALLA_API_KEY = -
MAL_BAZAR_API_KEY = -
INTEZER_API_KEY = -
PROXY = -

# URL of the internal retrohunt-analyzer-service (POST /api/v1/reports)
# Leave as - to disable. Example: http://retrohunt-analyzer.internal:8000
RETROHUNT_ANALYZER_URL = -
```

- [ ] **Step 2: Commit**

```bash
git add munin.ini
git commit -m "config: add RETROHUNT_ANALYZER_URL key to munin.ini template"
```

---

## Task 3: Write the failing unit tests

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/test_hugin_analyzer.py`

- [ ] **Step 1: Create the tests package**

```bash
mkdir -p tests
touch tests/__init__.py
```

- [ ] **Step 2: Write the test file**

Create `tests/test_hugin_analyzer.py`:

```python
"""Unit tests for hugin.send_to_analyzer()."""
import io
import os
import sys
import unittest
import zipfile
from unittest.mock import MagicMock, patch

# hugin.py lives one level up from tests/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hugin


def _make_zip(files: dict) -> bytes:
    """Build an in-memory ZIP with the given {filename: content_bytes} mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


class TestSendToAnalyzer(unittest.TestCase):

    def setUp(self):
        # Use a temp dir so we never write to the real filesystem
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.csv_path = os.path.join(self.tmp, "retrohunt_results.csv")
        # Create a dummy CSV so open() inside send_to_analyzer works
        with open(self.csv_path, "w") as f:
            f.write("Lookup Hash;Rating\nabc123;clean\n")

    # --- Happy path: HTML only (Valhalla not configured on service) ---
    def test_html_only_is_written_when_no_enriched_csv(self):
        zip_bytes = _make_zip({
            "retrohunt_results.html": b"<html>report</html>",
        })
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = zip_bytes

        with patch("hugin.requests.post", return_value=mock_resp):
            hugin.send_to_analyzer(self.csv_path, "http://analyzer.internal:8000")

        html_path = os.path.join(self.tmp, "retrohunt_results.html")
        self.assertTrue(os.path.exists(html_path))
        with open(html_path, "rb") as f:
            self.assertEqual(f.read(), b"<html>report</html>")

        # Enriched CSV must NOT be created
        enriched_path = os.path.join(self.tmp, "retrohunt_results_enriched.csv")
        self.assertFalse(os.path.exists(enriched_path))

    # --- Happy path: HTML + enriched CSV (Valhalla active on service) ---
    def test_html_and_enriched_csv_both_written(self):
        zip_bytes = _make_zip({
            "retrohunt_results.html": b"<html>report</html>",
            "retrohunt_results_enriched.csv": b"Lookup Hash;THOR Rules\nabc123;rule1\n",
        })
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = zip_bytes

        with patch("hugin.requests.post", return_value=mock_resp):
            hugin.send_to_analyzer(self.csv_path, "http://analyzer.internal:8000")

        html_path = os.path.join(self.tmp, "retrohunt_results.html")
        enriched_path = os.path.join(self.tmp, "retrohunt_results_enriched.csv")
        self.assertTrue(os.path.exists(html_path))
        self.assertTrue(os.path.exists(enriched_path))

    # --- Service returns non-200: should warn, not raise ---
    def test_non_200_response_does_not_raise(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"

        with patch("hugin.requests.post", return_value=mock_resp):
            # Must not raise
            hugin.send_to_analyzer(self.csv_path, "http://analyzer.internal:8000")

    # --- Network error: should warn, not raise ---
    def test_connection_error_does_not_raise(self):
        with patch("hugin.requests.post", side_effect=Exception("Connection refused")):
            hugin.send_to_analyzer(self.csv_path, "http://analyzer.internal:8000")

    # --- Correct endpoint is called ---
    def test_posts_to_correct_endpoint(self):
        zip_bytes = _make_zip({"report.html": b"<html/>"})
        mock_resp = MagicMock(status_code=200, content=zip_bytes)

        with patch("hugin.requests.post", return_value=mock_resp) as mock_post:
            hugin.send_to_analyzer(self.csv_path, "http://analyzer.internal:8000")

        call_args = mock_post.call_args
        self.assertEqual(
            call_args[0][0],
            "http://analyzer.internal:8000/api/v1/reports",
        )

    # --- Trailing slash in URL is handled ---
    def test_trailing_slash_in_url_is_handled(self):
        zip_bytes = _make_zip({"report.html": b"<html/>"})
        mock_resp = MagicMock(status_code=200, content=zip_bytes)

        with patch("hugin.requests.post", return_value=mock_resp) as mock_post:
            hugin.send_to_analyzer(self.csv_path, "http://analyzer.internal:8000/")

        call_url = mock_post.call_args[0][0]
        self.assertFalse(call_url.startswith("http://analyzer.internal:8000//"),
                         f"Double-slash in URL: {call_url}")

    # --- Output files land in the same directory as the CSV ---
    def test_output_files_go_to_csv_directory(self):
        zip_bytes = _make_zip({
            "report.html": b"<html/>",
            "report_enriched.csv": b"col1;col2\n",
        })
        mock_resp = MagicMock(status_code=200, content=zip_bytes)

        with patch("hugin.requests.post", return_value=mock_resp):
            hugin.send_to_analyzer(self.csv_path, "http://analyzer.internal:8000")

        for name in ("report.html", "report_enriched.csv"):
            path = os.path.join(self.tmp, name)
            self.assertTrue(os.path.exists(path), f"Expected {path} to exist")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run tests to confirm they fail (function not yet defined)**

```bash
python -m pytest tests/test_hugin_analyzer.py -v
```

Expected: `AttributeError: module 'hugin' has no attribute 'send_to_analyzer'` (or import errors) — all tests fail.

---

## Task 4: Implement `send_to_analyzer()` in `hugin.py`

**Files:**
- Modify: `hugin.py` (add function between imports and `main()`)

- [ ] **Step 1: Add `import io` and `import zipfile` to the imports block**

`hugin.py` already imports `requests`, `os`, and `traceback`. Both `io` and `zipfile`
are **not** imported — add both. They are stdlib modules, no install needed.

After line 17 (`import traceback`), insert:

```python
import io
import zipfile
```

Resulting tail of the imports block:

```python
import time
import traceback
import io
import zipfile
```

- [ ] **Step 2: Add `send_to_analyzer()` before `def main():`**

Insert the following function between the imports block and `def main():` (i.e., before line 27):

```python
def send_to_analyzer(csv_path: str, url: str) -> None:
    """POST *csv_path* to the retrohunt-analyzer-service and write the
    returned files (HTML report + optional enriched CSV) next to the CSV.

    The service endpoint is ``POST {url}/api/v1/reports`` which returns an
    ``application/zip`` archive.  Any file inside the ZIP is extracted to the
    same directory as *csv_path*.

    All errors are caught and printed as warnings so the caller's flow is
    never interrupted.

    Args:
        csv_path: Path to the retrohunt results CSV produced by hugin.
        url: Base URL of the retrohunt-analyzer-service, e.g.
             ``http://retrohunt-analyzer.internal:8000``.
    """
    endpoint = url.rstrip("/") + "/api/v1/reports"
    out_dir = os.path.dirname(os.path.abspath(csv_path))

    print("[*] Sending retrohunt CSV to analyzer service: %s" % endpoint)
    try:
        with open(csv_path, "rb") as fh:
            response = requests.post(
                endpoint,
                files={"file": (os.path.basename(csv_path), fh, "text/csv")},
                timeout=120,
            )
    except Exception as exc:
        print("[W] Could not reach retrohunt-analyzer-service: %s" % exc)
        return

    if response.status_code != 200:
        print("[W] Retrohunt-analyzer-service returned HTTP %d: %s"
              % (response.status_code, response.text[:200]))
        return

    try:
        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            names = zf.namelist()
            for name in names:
                out_path = os.path.join(out_dir, os.path.basename(name))
                with zf.open(name) as src, open(out_path, "wb") as dst:
                    dst.write(src.read())
                print("[+] Analyzer output saved: %s" % out_path)
    except Exception as exc:
        print("[W] Failed to extract analyzer response: %s" % exc)
        return

    enriched = any(n.endswith("_enriched.csv") for n in names)
    if enriched:
        print("[+] Enriched CSV included (Valhalla configured on service)")
    else:
        print("[*] No enriched CSV in response (Valhalla not configured on service)")
```

- [ ] **Step 3: Run the unit tests — all should pass now**

```bash
python -m pytest tests/test_hugin_analyzer.py -v
```

Expected: All 7 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add hugin.py tests/__init__.py tests/test_hugin_analyzer.py
git commit -m "feat: add send_to_analyzer() to hugin for retrohunt-analyzer-service integration"
```

---

## Task 5: Wire `send_to_analyzer()` into the main flow

**Files:**
- Modify: `hugin.py:60-85` (config reading and main loop)

- [ ] **Step 1: Read `RETROHUNT_ANALYZER_URL` from config**

In `main()`, inside the `try` block that reads config (around line 64), after the proxy is read (after line 66), add:

```python
        analyzer_url = config['DEFAULT'].get('RETROHUNT_ANALYZER_URL', '-').strip()
```

The full config-reading block should look like:

```python
    config = configparser.ConfigParser()
    try:
        config.read(args.i)
        munin_vt.VT_PUBLIC_API_KEY = config['DEFAULT']['VT_PUBLIC_API_KEY']
        try:
            connections.setProxy(config['DEFAULT']['PROXY'])
        except KeyError as e:
            print("[E] Your config misses the PROXY field - check the new munin.ini template and add it to your "
                  "config to avoid this error.")
        analyzer_url = config['DEFAULT'].get('RETROHUNT_ANALYZER_URL', '-').strip()
    except Exception as e:
        traceback.print_exc()
        print("[E] Config file '%s' not found or missing field - check the template munin.ini if fields have "
              "changed" % args.i)
        analyzer_url = '-'
```

- [ ] **Step 2: Call `send_to_analyzer()` after the CSV write loop**

After line 85 (`writeCSV(file_info, csv_filename)`), add:

```python
    if analyzer_url and analyzer_url != '-':
        send_to_analyzer(csv_filename, analyzer_url)
    else:
        print("[*] RETROHUNT_ANALYZER_URL not configured — skipping analyzer service")
```

The bottom of `main()` should look like:

```python
    for i, file_info in enumerate(found_files):
        printResult(file_info, i, len(found_files))
        writeCSV(file_info, csv_filename)

    if analyzer_url and analyzer_url != '-':
        send_to_analyzer(csv_filename, analyzer_url)
    else:
        print("[*] RETROHUNT_ANALYZER_URL not configured — skipping analyzer service")


if __name__ == '__main__':
    main()
```

- [ ] **Step 3: Run unit tests again to confirm nothing regressed**

```bash
python -m pytest tests/test_hugin_analyzer.py -v
```

Expected: All 7 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add hugin.py
git commit -m "feat: call send_to_analyzer() in hugin main() when URL is configured"
```

---

## Task 6: Integration smoke-test

> No automated test is practical here because the service is internal. Follow these manual steps.

**Scenario A — URL not configured (default, backward compat)**

- [ ] Run with `-` as URL value (the default):

```bash
python hugin.py -r <your-retrohunt-name>
```

Expected output includes: `[*] RETROHUNT_ANALYZER_URL not configured — skipping analyzer service`

No extra files created beyond `retrohunt_results.csv`. Existing behavior unchanged.

---

**Scenario B — URL configured, service reachable, Valhalla not active**

- [ ] Set `RETROHUNT_ANALYZER_URL = http://<service-host>:<port>` in your `munin.ini`.
- [ ] Run:

```bash
python hugin.py -r <your-retrohunt-name>
```

Expected:
```
[*] Sending retrohunt CSV to analyzer service: http://<host>/api/v1/reports
[+] Analyzer output saved: retrohunt_results.html
[*] No enriched CSV in response (Valhalla not configured on service)
```

Files present: `retrohunt_results.csv`, `retrohunt_results.html` (2 files).

---

**Scenario C — URL configured, service reachable, Valhalla active**

Expected additional line:
```
[+] Analyzer output saved: retrohunt_results_enriched.csv
[+] Enriched CSV included (Valhalla configured on service)
```

Files present: `retrohunt_results.csv`, `retrohunt_results.html`, `retrohunt_results_enriched.csv` (3 files).

---

**Scenario D — Service unreachable**

- [ ] Configure a bogus URL: `RETROHUNT_ANALYZER_URL = http://localhost:19999`
- [ ] Run:

```bash
python hugin.py -r <your-retrohunt-name>
```

Expected: `[W] Could not reach retrohunt-analyzer-service: ...` — CSV is still written normally.

---

## Task 7: Final commit and summary

- [ ] **Step 1: Verify all tests still pass**

```bash
python -m pytest tests/test_hugin_analyzer.py -v
```

Expected: 7/7 PASS.

- [ ] **Step 2: Final commit if any cleanup was done**

```bash
git add -p   # stage only intentional changes
git commit -m "chore: cleanup retrohunt-analyzer integration"
```

- [ ] **Step 3: Confirm branch state**

```bash
git log --oneline feature/retrohunt-analyzer-integration
```

Expected: 3-4 commits visible — branch creation, config change, send_to_analyzer implementation, main() wiring.

---

## Output File Summary

| File | Always present? | Notes |
|------|-----------------|-------|
| `<csv-path>.csv` | Yes | Original munin retrohunt results (existing behavior) |
| `<csv-path>.html` or same stem | If URL configured | HTML report from retrohunt-analyzer-service |
| `<csv-path>_enriched.csv` or same stem | If Valhalla enabled on service | Enriched CSV with THOR rule matches |

The exact filenames inside the ZIP are determined by the service (stem = uploaded filename stem). All files from the ZIP are extracted to the same directory as the uploaded CSV.
