#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys

import joern2sarif.lib.convert as convertLib
from joern2sarif.lib.logger import LOG


def build_args():
    """
    Constructs command line arguments for the vulndb tool
    """
    parser = argparse.ArgumentParser(
        description="Utility script to convert joern/ocular json output to sarif."
    )
    parser.add_argument(
        "-i", "--src", dest="src_file", help="Source file", required=True
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        default="joern-report.sarif",
        help="Report filename with directory",
    )
    parser.add_argument(
        "-t",
        "--tool",
        dest="tool_name",
        choices=["joern", "ocular", "ng-sast"],
        default="joern",
        help="Tool name",
    )
    return parser.parse_args()


def main():
    args = build_args()
    src_file = args.src_file
    if not os.path.exists(src_file):
        print(f"{src_file} doesn't exist")
        sys.exit(1)
    report_file = args.report_file
    reports_dir = os.path.dirname(report_file)
    # Create reports directory
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    work_dir = os.getcwd()
    for e in ["GITHUB_WORKSPACE", "WORKSPACE"]:
        if os.getenv(e):
            work_dir = os.getenv(e)
            break
    LOG.debug(f"About to convert {src_file}")
    sarif_data = convertLib.convert_file(
        args.tool_name,
        os.getenv("TOOL_ARGS", ""),
        work_dir,
        src_file,
        report_file,
        None,
    )
    if sarif_data:
        LOG.info(f"SARIF file created successfully at {report_file}")


if __name__ == "__main__":
    main()
