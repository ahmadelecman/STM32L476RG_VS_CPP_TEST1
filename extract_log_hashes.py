import sys
import os
import re
import json

# NOTE: This script does NOT modify any source files. It only reads them.

def hash_string(s):
    hash = 2166136261
    for c in s:
        hash = (hash ^ ord(c)) * 16777619
        hash &= 0xFFFFFFFF
    return hash

# Regex to match LOG_INFO("..."), LOG_WARN("..."), etc. on a single line
log_macro = re.compile(r'LOG_(DEBUG|INFO|WARN|ERROR|FATAL)\s*\(\s*"([^"]+)"')

def remove_comments(text):
    # Remove all // comments
    text = re.sub(r'//.*', '', text)
    # Remove all /* ... */ comments (including multi-line)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    return text

hashes = {}

source_dirs = sys.argv[1:-1]
output_file = sys.argv[-1]

# Clean the previous output file if it exists
if os.path.exists(output_file):
    os.remove(output_file)

for src_dir in source_dirs:
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith(('.c', '.cpp', '.h', '.hpp')):
                file_path = os.path.join(root, file)
                with open(file_path, encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    content = remove_comments(content)
                    for match in log_macro.finditer(content):
                        fmt = match.group(2)
                        h = hash_string(fmt)
                        hashes[f"{h:08X}"] = fmt

print(f"\nWriting {len(hashes)} log strings to {output_file}")
with open(output_file, 'w', encoding='utf-8') as out:
    json.dump(hashes, out, indent=4, ensure_ascii=False)