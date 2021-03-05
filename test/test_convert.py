import json
import os
from pathlib import Path

import pytest

import joern2sarif.lib.convert as convertLib


@pytest.fixture
def test_findings():
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    json_file = os.path.join(curr_dir, "data", "sample-findings.json")
    with open(json_file) as fp:
        return json.load(fp)


@pytest.fixture
def test_issues():
    issues = convertLib.extract_from_file(
        "joern",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "sample-findings.json",
    )
    return issues


def test_joern_extract_issue():
    issues = convertLib.extract_from_file(
        "joern",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "sample-findings.json",
    )
    assert issues
    assert len(issues) == 38
    assert issues[0] == {
        "rule_id": "http-to-log",
        "title": "Sensitive Data Leak",
        "short_description": "Sensitive Data Leak",
        "description": "Sensitive Data Leak: Security-sensitive data is leaked via `req` to log in `anonymous`\n\nHTTP data is written to a log file in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.\n\n\n## Countermeasures\n\nThis vulnerability can be prevented by not writing HTTP data directly to the log or by encrypting it in advance.\n\n## Additional information\n\n**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**\n\n**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**\n\n**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**",
        "issue_severity": "2.5",
        "line_number": 6,
        "filename": "vulnerabilities/sensitive.js",
        "issue_confidence": "HIGH",
    }


def test_sample_convert(test_issues):
    data = convertLib.report(issues=test_issues)
    jsondata = json.loads(data)
    assert (
        jsondata["runs"][0]["automationDetails"]["description"]["text"]
        == "Static Analysis Security Test results using joern"
    )
