# Collect all .rs files in a directory into a single text file

# Usage: just collect src my_source_code.txt
collect dir output_file:
    #!/usr/bin/env bash
    set -euo pipefail

    # Clear or create the output file
    truncate -s 0 {{ output_file }}

    echo "📂 Collecting .rs files from '{{ dir }}' into '{{ output_file }}'..."

    # Find all .rs files
    # 1. Prints the relative path
    # 2. Dumps the file content
    # 3. Prints the separator
    find "{{ dir }}" -name "*.rs" -type f | while read -r file; do
        echo -e "// $file\n" >> {{ output_file }}
        cat "$file" >> {{ output_file }}
        echo -e "\n---" >> {{ output_file }}
    done

    echo "✅ Done. Total files: $(find "{{ dir }}" -name "*.rs" | wc -l)"

collect-all:
    @just collect src signal_x3dh.txt
    @just collect tests signal_x3dh_tests.txt
    @just collect fuzz/fuzz_targets signal_x3dh_fuzz_targets.txt
    @just collect benches signal_x3dh_benches.txt
