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
        "fingerprint": "0faab86059cec4d8e185382166a9f583",
    }


def test_ngsast_extract_issue():
    issues = convertLib.extract_from_file(
        "ng-sast",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "ngsast-report.json",
    )
    assert issues
    assert len(issues) == 29
    assert issues[0] == {
        "rule_id": "command-injection-http",
        "title": "Remote Code Execution",
        "description": "Remote Code Execution: Command Injection through HTTP via `req` in `anonymous1`\n\nHTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.\n\n\n## Countermeasures\n\nThis vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.\n\n## Additional information\n\n**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**\n\n**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**\n\n**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**\n\n**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**",
        "score": 9,
        "severity": "critical",
        "line_number": "19",
        "filename": "vulnerabilities/exec.js",
        "first_found": "1545c906d065bb4eb4c863be85d318e0b8cb509d",
        "issue_confidence": "HIGH",
        "fingerprint": "3fdf32776d26f1c3d469859fd6a46600",
    }


def test_sample_convert(test_issues):
    data = convertLib.report(issues=test_issues)
    jsondata = json.loads(data)
    assert (
        jsondata["runs"][0]["automationDetails"]["description"]["text"]
        == "Static Analysis Security Test results using joern"
    )
