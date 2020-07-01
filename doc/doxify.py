#!/usr/bin/env python3

import argparse
from pathlib import Path
import re
import os
import shutil

SUBPAGE_RE = re.compile(r"\[[^\]]+\]\s*\(([^\)]+)\.md\s*\)", re.MULTILINE)
TAG_RE = re.compile(r"(#.*)\n", re.MULTILINE)

parser = argparse.ArgumentParser(description='Modfiy .md files to be doxygen compatible')
parser.add_argument('source_dir', type=str, help='Directory containing the .md files')
parser.add_argument('dest_dir', type=str, help='Directory the modified files are written action')

args = parser.parse_args()

shutil.rmtree(args.dest_dir, ignore_errors=True)
os.makedirs(args.dest_dir)

for md_path in Path(args.source_dir).glob('*.md'):
    content = md_path.read_text()

    if "example_main_page.md" in str(md_path):
        content = SUBPAGE_RE.sub(r"@subpage \1", content)

    content = TAG_RE.sub(r"\1 {#" + md_path.name[:-3] + "}\n", content, count=1)

    (Path(args.dest_dir) / md_path.name).write_text(content)
