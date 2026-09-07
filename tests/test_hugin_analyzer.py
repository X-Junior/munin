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
