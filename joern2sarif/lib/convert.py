import datetime
import io
import json
import os
import pathlib
import re
import uuid
from urllib.parse import quote_plus

import sarif_om as om
from jschema_to_python.to_json import to_json

import joern2sarif.lib.config as config
from joern2sarif.lib.issue import issue_from_dict

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def convert_dataflow(dataflows):
    """
    Convert dataflow into a simpler source and sink format for better representation in SARIF based viewers

    :param dataflows: List of dataflows from Inspect
    :return List of filename and location
    """
    if not dataflows:
        return None
    loc_list = []
    for flow in dataflows:
        location = flow.get("location")
        if not location.get("file_name") or not location.get("line_number"):
            continue
        loc_list.append(
            {
                "filename": location.get("file_name"),
                "line_number": location.get("line_number"),
            }
        )
    return loc_list


def extract_from_file(
    tool_name, tool_args, working_dir, report_file, file_path_list=None
):
    """Extract properties from reports

    :param tool_name: tool name
    :param tool_args: tool args
    :param working_dir: Working directory
    :param report_file: Report file
    :param file_path_list: Full file path for any manipulation

    :return issues, metrics, skips information
    """
    issues = []
    # If the tools did not produce any result do not crash
    if not os.path.isfile(report_file):
        return issues
    extn = pathlib.PurePosixPath(report_file).suffix

    with io.open(report_file, "r") as rfile:
        if extn == ".json":
            try:
                report_data = json.loads(rfile.read())
            except json.decoder.JSONDecodeError:
                return issues
            # Joern
            if tool_name in ["joern", "ocular"]:
                for v in report_data:
                    if not v or not v.get("_label") == "FINDING":
                        continue
                    keyValuePairs = v.get("keyValuePairs")
                    kvdict = {}
                    for kv in keyValuePairs:
                        if kv.get("_label") == "KEY_VALUE_PAIR":
                            kvdict[kv["key"]] = kv["value"]
                    evidence = v.get("evidence")
                    fingerprint = None
                    source = None
                    sink = None
                    for ev in evidence:
                        if not fingerprint:
                            fingerprint = ev.get("fingerprint")
                        source_obj = ev.get("source")
                        if (
                            source_obj
                            and source_obj.get("method")
                            and source_obj.get("method", {}).get("filename")
                        ):
                            source = {
                                "filename": source_obj.get("method").get("filename"),
                                "line_number": source_obj.get("method").get(
                                    "lineNumber"
                                ),
                                "fullName": source_obj.get("method").get("fullName"),
                            }
                        sink_obj = ev.get("sink")
                        if sink_obj:
                            if sink_obj.get("method") and sink_obj.get(
                                "method", {}
                            ).get("filename"):
                                sink = {
                                    "filename": sink_obj.get("method").get("filename"),
                                    "line_number": sink_obj.get("method").get(
                                        "lineNumber"
                                    ),
                                    "fullName": sink_obj.get("method").get("fullName"),
                                }
                            elif sink_obj.get("callingMethod") and sink_obj.get(
                                "callingMethod", {}
                            ).get("filename"):
                                sink = {
                                    "filename": sink_obj.get("callingMethod").get(
                                        "filename"
                                    ),
                                    "line_number": sink_obj.get("callingMethod").get(
                                        "lineNumber"
                                    ),
                                    "fullName": sink_obj.get("callingMethod").get(
                                        "fullName"
                                    ),
                                }
                        if fingerprint and (source or sink):
                            break
                    issues.append(
                        {
                            "rule_id": kvdict["name"],
                            "title": kvdict["VulnerabilityDescription"],
                            "short_description": kvdict["VulnerabilityDescription"],
                            "description": kvdict["TitleTemplate"]
                            + "\n\n"
                            + kvdict["DescriptionTemplate"],
                            "issue_severity": kvdict["Score"],
                            "line_number": sink.get("line_number")
                            if sink
                            else source.get("line_number"),
                            "filename": sink.get("filename")
                            if sink
                            else source.get("filename"),
                            "issue_confidence": "HIGH",
                            "fingerprint": fingerprint,
                        }
                    )
            # NG SAST (Formerly Inspect) uses vulnerabilities
            elif tool_name == "ng-sast":
                for k, v in report_data.items():
                    if not v:
                        continue
                    for vuln in v:
                        location = {}
                        details = vuln.get("details", {})
                        file_locations = details.get("file_locations", [])
                        tags = vuln.get("tags", [])
                        internal_id = vuln.get("internal_id")
                        tmpA = internal_id.split("/")
                        rule_id = tmpA[0]
                        fingerprint = tmpA[-1]
                        score = ""
                        cvss_tag = [t for t in tags if t.get("key") == "cvss_score"]
                        if cvss_tag:
                            score = cvss_tag[0].get("value")
                        if file_locations:
                            last_loc = file_locations[-1]
                            loc_arr = last_loc.split(":")
                            location = {
                                "filename": loc_arr[0],
                                "line_number": loc_arr[1],
                            }
                        if not location and details.get("dataflow"):
                            dataflows = details.get("dataflow").get("list")
                            if dataflows:
                                location_list = convert_dataflow(dataflows)
                                # Take the sink
                                if location_list:
                                    location = location_list[-1]
                        if location:
                            issues.append(
                                {
                                    "rule_id": rule_id,
                                    "title": vuln["category"],
                                    "description": vuln["title"]
                                    + "\n\n"
                                    + vuln["description"],
                                    "score": score,
                                    "severity": vuln["severity"],
                                    "line_number": location.get("line_number"),
                                    "filename": location.get("filename"),
                                    "first_found": vuln["version_first_seen"],
                                    "issue_confidence": "HIGH",
                                    "fingerprint": fingerprint,
                                }
                            )
    return issues


def convert_file(
    tool_name,
    tool_args,
    working_dir,
    report_file,
    converted_file,
    file_path_list=None,
):
    """Convert report file

    :param tool_name: tool name
    :param tool_args: tool args
    :param working_dir: Working directory
    :param report_file: Report file
    :param converted_file: Converted file
    :param file_path_list: Full file path for any manipulation

    :return serialized_log: SARIF output data
    """
    issues = extract_from_file(
        tool_name, tool_args, working_dir, report_file, file_path_list
    )
    return report(
        tool_name=tool_name,
        tool_args=tool_args,
        working_dir=working_dir,
        issues=issues,
        crep_fname=converted_file,
        file_path_list=file_path_list,
    )


def report(
    tool_name="joern",
    tool_args=["--script", "oc_scripts/scan.sc"],
    working_dir=os.getcwd(),
    issues=None,
    crep_fname="joern-report.sarif",
    file_path_list=None,
):
    """Prints issues in SARIF format

    :param tool_name: tool name
    :param tool_args: Args used for the tool
    :param working_dir: Working directory
    :param issues: issues data
    :param crep_fname: The output file name
    :param file_path_list: Full file path for any manipulation

    :return serialized_log: SARIF output data
    """
    if not tool_args:
        tool_args = []
    tool_args_str = tool_args
    if isinstance(tool_args, list):
        tool_args_str = " ".join(tool_args)
    log_uuid = str(uuid.uuid4())
    run_uuid = str(uuid.uuid4())

    # working directory to use in the log
    WORKSPACE_PREFIX = os.getenv("WORKSPACE", None)
    wd_dir_log = WORKSPACE_PREFIX if WORKSPACE_PREFIX is not None else working_dir
    driver_name = config.driver_name
    # Construct SARIF log
    log = om.SarifLog(
        schema_uri="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version="2.1.0",
        inline_external_properties=[
            om.ExternalProperties(guid=log_uuid, run_guid=run_uuid)
        ],
        runs=[
            om.Run(
                automation_details=om.RunAutomationDetails(
                    guid=log_uuid,
                    description=om.Message(
                        text=f"Static Analysis Security Test results using {tool_name}"
                    ),
                ),
                tool=om.Tool(
                    driver=om.ToolComponent(
                        name=driver_name,
                        information_uri="https://joern.io",
                        full_name=driver_name,
                        version="1.0.0",
                    )
                ),
                invocations=[
                    om.Invocation(
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                        execution_successful=True,
                        working_directory=om.ArtifactLocation(uri=to_uri(wd_dir_log)),
                    )
                ],
                conversion={
                    "tool": om.Tool(driver=om.ToolComponent(name=tool_name)),
                    "invocation": om.Invocation(
                        execution_successful=True,
                        command_line=tool_args_str,
                        arguments=tool_args,
                        working_directory=om.ArtifactLocation(uri=to_uri(wd_dir_log)),
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                    ),
                },
            )
        ],
    )
    run = log.runs[0]
    add_results(tool_name, issues, run, file_path_list, working_dir)
    serialized_log = to_json(log)
    if crep_fname:
        with io.open(crep_fname, "w") as fileobj:
            fileobj.write(serialized_log)
    return serialized_log


def add_results(tool_name, issues, run, file_path_list=None, working_dir=None):
    """Method to convert issues into results schema

    :param tool_name: tool name
    :param issues: Issues found
    :param run: Run object
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    if run.results is None:
        run.results = []

    rules = {}
    rule_indices = {}

    for issue in issues:
        result = create_result(
            tool_name, issue, rules, rule_indices, file_path_list, working_dir
        )
        if result:
            run.results.append(result)
    if len(rules) > 0:
        run.tool.driver.rules = list(rules.values())


def create_result(tool_name, issue, rules, rule_indices, file_path_list, working_dir):
    """Method to convert a single issue into result schema with rules

    :param tool_name: tool name
    :param issue: Issues object
    :param rules: List of rules
    :param rule_indices: Indices of referred rules
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    WORKSPACE_PREFIX = os.getenv("WORKSPACE", None)
    if isinstance(issue, dict):
        issue = issue_from_dict(issue)

    issue_dict = issue.as_dict()
    rule, rule_index = create_or_find_rule(tool_name, issue_dict, rules, rule_indices)

    # Substitute workspace prefix
    # Override file path prefix with workspace
    filename = issue_dict["filename"]
    if working_dir:
        # Convert to full path only if the user wants
        if WORKSPACE_PREFIX is None and not filename.startswith(working_dir):
            filename = os.path.join(working_dir, filename)
        if WORKSPACE_PREFIX is not None:
            # Make it relative path
            if WORKSPACE_PREFIX == "":
                filename = re.sub(r"^" + working_dir + "/", WORKSPACE_PREFIX, filename)
            elif not filename.startswith(working_dir):
                filename = os.path.join(WORKSPACE_PREFIX, filename)
            else:
                filename = re.sub(r"^" + working_dir, WORKSPACE_PREFIX, filename)
    physical_location = om.PhysicalLocation(
        artifact_location=om.ArtifactLocation(uri=to_uri(filename))
    )

    add_region_and_context_region(
        physical_location, issue_dict["line_number"], issue_dict["code"]
    )
    issue_severity = issue_dict["issue_severity"]
    fingerprint = {"evidenceFingerprint": issue_dict["line_hash"]}

    return om.Result(
        rule_id=rule.id,
        rule_index=rule_index,
        message=om.Message(
            text=issue_dict["issue_text"],
            markdown=issue_dict["issue_text"],
        ),
        level=level_from_severity(issue_severity),
        locations=[om.Location(physical_location=physical_location)],
        partial_fingerprints=fingerprint,
        properties={
            "issue_confidence": issue_dict["issue_confidence"],
            "issue_severity": issue_severity,
            "issue_tags": issue_dict.get("tags", {}),
        },
        baseline_state="unchanged" if issue_dict["first_found"] else "new",
    )


def level_from_severity(severity):
    """Converts tool's severity to the 4 level
    suggested by SARIF
    """
    if severity == "CRITICAL":
        return "error"
    elif severity == "HIGH":
        return "error"
    elif severity == "MEDIUM":
        return "warning"
    elif severity == "LOW":
        return "note"
    else:
        return "warning"


def add_region_and_context_region(physical_location, line_number, code):
    """This adds the region information for displaying the code snippet

    :param physical_location: Points to file
    :param line_number: Line number suggested by the tool
    :param code: Source code snippet
    """
    first_line_number, snippet_lines = parse_code(code)
    # Ensure start line is always non-zero
    if first_line_number == 0:
        first_line_number = 1
    end_line_number = first_line_number + len(snippet_lines) - 1
    if end_line_number < first_line_number:
        end_line_number = first_line_number + 3
    index = line_number - first_line_number
    snippet_line = ""
    if line_number == 0:
        line_number = 1
    if snippet_lines and len(snippet_lines) > index:
        if index > 0:
            snippet_line = snippet_lines[index]
        else:
            snippet_line = snippet_lines[0]
    if snippet_line.strip().replace("\n", "") == "":
        snippet_line = ""
    physical_location.region = om.Region(
        start_line=line_number, snippet=om.ArtifactContent(text=snippet_line)
    )

    physical_location.context_region = om.Region(
        start_line=first_line_number,
        end_line=end_line_number,
        snippet=om.ArtifactContent(text="".join(snippet_lines)),
    )


def parse_code(code):
    """Method to parse the code to extract line number and snippets"""
    code_lines = code.split("\n")

    # The last line from the split has nothing in it; it's an artifact of the
    # last "real" line ending in a newline. Unless, of course, it doesn't:
    last_line = code_lines[len(code_lines) - 1]

    last_real_line_ends_in_newline = False
    if len(last_line) == 0:
        code_lines.pop()
        last_real_line_ends_in_newline = True

    snippet_lines = []
    first = True
    first_line_number = 1
    for code_line in code_lines:
        number_and_snippet_line = code_line.split(" ", 1)
        if first:
            first_line_number = int(number_and_snippet_line[0])
            first = False
        if len(number_and_snippet_line) > 1:
            snippet_line = number_and_snippet_line[1] + "\n"
            snippet_lines.append(snippet_line)

    if not last_real_line_ends_in_newline:
        last_line = snippet_lines[len(snippet_lines) - 1]
        snippet_lines[len(snippet_lines) - 1] = last_line[: len(last_line) - 1]

    return first_line_number, snippet_lines


def get_rule_short_description(tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a short description for the rule

    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return:
    """
    if issue_dict.get("short_description"):
        return issue_dict.get("short_description")
    return "Rule {} from {}.".format(rule_id, tool_name)


def get_rule_full_description(tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a full description for the rule

    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return:
    """
    if issue_dict.get("description"):
        return issue_dict.get("description")
    issue_text = issue_dict.get("issue_text", "")
    # Extract just the first line alone
    if issue_text:
        issue_text = issue_text.split("\n")[0]
    if not issue_text.endswith("."):
        issue_text = issue_text + "."
    return issue_text


def get_help(format, tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a full description for the rule

    :param format: text or markdown
    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return: Help text
    """
    issue_text = issue_dict.get("issue_text", "")
    return issue_text


def get_url(tool_name, rule_id, test_name, issue_dict):
    if issue_dict.get("test_ref_url"):
        return issue_dict.get("test_ref_url")
    rule_id = quote_plus(rule_id)
    if rule_id and rule_id.startswith("CWE"):
        return "https://cwe.mitre.org/data/definitions/%s.html" % rule_id.replace(
            "CWE-", ""
        )
    if issue_dict.get("cwe_category"):
        return "https://cwe.mitre.org/data/definitions/%s.html" % issue_dict.get(
            "cwe_category"
        ).replace("CWE-", "")
    return "https://joern.io?q={}".format(rule_id)


def create_or_find_rule(tool_name, issue_dict, rules, rule_indices):
    """Creates rules object for the rules section. Different tools make up
        their own id and names so this is identified on the fly

    :param tool_name: tool name
    :param issue_dict: Issue object that is normalized and converted
    :param rules: List of rules identified so far
    :param rule_indices: Rule indices cache

    :return rule and index
    """
    rule_id = issue_dict["test_id"]
    rule_name = issue_dict["test_name"]
    if rule_id == rule_name:
        rule_name = rule_name.lower().replace("_", " ").capitalize()
    rule_name = rule_name.replace(" ", "")
    if rule_id in rules:
        return rules[rule_id], rule_indices[rule_id]
    precision = "very-high"
    issue_severity = issue_dict["issue_severity"]
    rule = om.ReportingDescriptor(
        id=rule_id,
        name=rule_name,
        short_description={
            "text": get_rule_short_description(
                tool_name, rule_id, issue_dict["test_name"], issue_dict
            )
        },
        full_description={
            "text": get_rule_full_description(
                tool_name, rule_id, issue_dict["test_name"], issue_dict
            )
        },
        help={
            "text": get_help(
                "text", tool_name, rule_id, issue_dict["test_name"], issue_dict
            ),
            "markdown": get_help(
                "markdown", tool_name, rule_id, issue_dict["test_name"], issue_dict
            ),
        },
        help_uri=get_url(tool_name, rule_id, issue_dict["test_name"], issue_dict),
        properties={
            "tags": ["joern"],
            "precision": precision,
        },
        default_configuration={"level": level_from_severity(issue_severity)},
    )

    index = len(rules)
    rules[rule_id] = rule
    rule_indices[rule_id] = index
    return rule, index


def to_uri(file_path):
    """Converts to file path to uri prefixed with file://

    :param file_path: File path to convert
    """
    if file_path.startswith("http"):
        return file_path
    if "\\" in file_path:
        if "/" in file_path:
            file_path = file_path.replace("/", "\\")
        pure_path = pathlib.PureWindowsPath(file_path)
    else:
        pure_path = pathlib.PurePath(file_path)
    if pure_path.is_absolute():
        return pure_path.as_uri()
    else:
        return pure_path.as_posix()  # Replace backslashes with slashes.
