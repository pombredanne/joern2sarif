#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys


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
    return parser.parse_args()


def main():
    args = build_args()
    src_file = args.src_file
    report_file = args.report_file
    reports_dir = os.path.dirname(report_file)
    # Create reports directory
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)


if __name__ == "__main__":
    main()
