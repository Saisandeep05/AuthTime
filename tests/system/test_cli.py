"""
System tests for AuthTime CLI interface.
"""

import pytest
import sys
from authtime.cli import create_parser


def test_cli_parser_run_command():
    parser = create_parser()
    args = parser.parse_args(["run", "--fault-type", "stale_cache", "--time-scale", "0.1", "--repetitions", "3"])
    assert args.command == "run"
    assert args.fault_type == "stale_cache"
    assert args.time_scale == 0.1
    assert args.repetitions == 3


def test_cli_parser_target_command():
    parser = create_parser()
    args = parser.parse_args(["target", "start", "--port", "8001"])
    assert args.command == "target"
    assert args.target_action == "start"
    assert args.port == 8001
