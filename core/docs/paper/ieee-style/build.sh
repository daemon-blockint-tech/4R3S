#!/bin/bash
# Build ARES V3 IEEE paper
cd "$(dirname "$0")"
pdflatex -interaction=nonstopmode main.tex 2>&1 | grep -A5 "Error"
bibtex main 2>&1
pdflatex -interaction=nonstopmode main.tex 2>&1 | grep -A5 "Error"
pdflatex -interaction=nonstopmode main.tex 2>&1 | grep -A5 "Error"
echo "=== Build complete ==="
[ -f main.pdf ] && echo "PDF generated: $(pwd)/main.pdf" || echo "PDF generation failed"
