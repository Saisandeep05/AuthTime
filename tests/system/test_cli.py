"""
System tests for AuthTime CLI.
"""

import sys
import pytest
from authtime.cli import create_parser


def test_cli_parser_help():
    parser = create_parser()
    args = parser.parse_args(["run", "--fault-type", "stale_cache", "--time-scale", "0.5"])
    assert args.command == "run"
    assert args.fault_type == "stale_cache"
    assert args.time_scale == 0.5


def test_cli_parser_target_start():
    parser = create_parser()
    args = parser.parse_args(["target", "start", "--port", "8000"])
    assert args.command == "target"
    assert args.target_action == "start"
    assert args.port == 8000
