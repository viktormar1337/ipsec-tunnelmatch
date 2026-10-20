#!/usr/bin/env python3
"""Kept for the README's earlier instructions: same as prepare_template.py with pfSense defaults."""
import os
import runpy
import sys

sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prepare_template.py")
runpy.run_path(sys.argv[0], run_name="__main__")
