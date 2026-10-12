import subprocess
import sys
from pathlib import Path


def test_pipeline_with_sample_xml():
    root = Path(__file__).resolve().parent.parent
    sample_xml = root / "samples" / "sample_nmap.xml"
    assert sample_xml.is_file()

    # Run app.py with --xml option
    cmd = [sys.executable, str(root / "app.py"), "--xml", str(sample_xml)]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=root)

    assert res.returncode == 0, f"app.py failed: {res.stderr}\n{res.stdout}"
    assert "SCAN COMPLETE" in res.stdout
    assert "Open Ports   : 5" in res.stdout
    assert "High Risk    : 1" in res.stdout

    # Clean up generated test output files so workspace stays clean
    (root / "reports" / "sample_target_example_report.md").unlink(missing_ok=True)
    (root / "results" / "dashboard.html").unlink(missing_ok=True)
    (root / "results" / "port_analysis.md").unlink(missing_ok=True)

    # Reset results/scan_results.csv and .json to blank template
    (root / "results" / "scan_results.csv").write_text("ip,hostname,port,protocol,state,service,product,version,extrainfo\n", encoding="utf-8")
    (root / "results" / "scan_results.json").write_text("[]\n", encoding="utf-8")


def test_pipeline_missing_xml():
    root = Path(__file__).resolve().parent.parent
    cmd = [sys.executable, str(root / "app.py"), "--xml", "non_existent_file.xml"]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=root)
    assert res.returncode != 0
    assert "XML file not found" in res.stderr or "XML file not found" in res.stdout
