import sys
import os
import re
import json

def hash_string(s):
    hash = 2166136261
    for c in s:
        hash = (hash ^ ord(c)) * 16777619
        hash &= 0xFFFFFFFF
    return hash

# Regex to match LOG_INFO("..."), LOG_WARN("..."), etc. on a single line
log_macro = re.compile(r'LOG_(DEBUG|INFO|WARN|ERROR|FATAL)\s*KATEX_INLINE_OPEN\s*"([^"]+)"')

hashes = {}

# Accept multiple source directories as arguments
source_dirs = sys.argv[1:-1]
output_file = sys.argv[-1]

print("Current working directory:", os.getcwd())
print("Source dirs:", source_dirs)
print("Contents of current directory:", os.listdir('.'))

for src_dir in source_dirs:
    print(f"\nListing files in {src_dir}:")
    for root, dirs, files in os.walk(src_dir):
        print("  In folder:", root)
        for file in files:
            print("    File:", file)
            if file.endswith(('.c', '.cpp', '.h', '.hpp')):
                file_path = os.path.join(root, file)
                with open(file_path, encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if "LOG_INFO" in line:
                            print("Line with LOG_INFO:", line.strip())
                            if log_macro.search(line):
                                print("  Regex matched!")
                            else:
                                print("  Regex did NOT match!")
                        for match in log_macro.finditer(line):
                            fmt = match.group(2)
                            h = hash_string(fmt)
                            print(f"  Found log string: \"{fmt}\" (hash: 0x{h:08X})")
                            hashes[f"{h:08X}"] = fmt

print(f"\nWriting {len(hashes)} log strings to {output_file}")
with open(output_file, 'w', encoding='utf-8') as out:
    json.dump(hashes, out, indent=4, ensure_ascii=False)

