#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${BACKEND_DIR}"

BUILD_DIR="build"
DIST_DIR="dist"
ZIP_FILE="${DIST_DIR}/lambda.zip"

# Determine Python executable
if [ -f "${BACKEND_DIR}/.venv/Scripts/python.exe" ]; then
    PYTHON_CMD="${BACKEND_DIR}/.venv/Scripts/python.exe"
elif [ -f "${BACKEND_DIR}/.venv/bin/python" ]; then
    PYTHON_CMD="${BACKEND_DIR}/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1 && python -m pip --version >/dev/null 2>&1; then
    PYTHON_CMD="python"
elif [ -f "/c/Users/aswan/AppData/Local/Programs/Python/Python313/python.exe" ]; then
    PYTHON_CMD="/c/Users/aswan/AppData/Local/Programs/Python/Python313/python.exe"
else
    echo "ERROR: Python executable not found" >&2
    exit 1
fi


echo "============================================================"
echo " Packaging VaultRAG Lambda (ARM64 / Python 3.12)"
echo " Using: ${PYTHON_CMD}"
echo "============================================================"

# 1. Clean build/ and dist/
echo "[1/5] Cleaning existing build and dist directories..."
rm -rf "${BUILD_DIR}" "${DIST_DIR}"
mkdir -p "${BUILD_DIR}" "${DIST_DIR}"

# 2. Install dependencies with manylinux2014_aarch64 binary wheels
echo "[2/5] Installing ARM64 binary wheels for Python 3.12..."

# Check if running under Windows / MSYS host where pip inspects local OS for markers
if [[ "${OSTYPE:-}" == "msys"* || "${OSTYPE:-}" == "win32"* || "${OSTYPE:-}" == "cygwin"* ]] || "$PYTHON_CMD" -c "import os, sys; sys.exit(0 if os.name == 'nt' else 1)" 2>/dev/null; then
    echo "  --> Detected Windows host; evaluating dependency markers for Linux ARM64 target..."
    "$PYTHON_CMD" -c "
import sys
try:
    import pip._vendor.packaging.markers as m
    orig = m.default_environment
    def mock_env():
        e = orig()
        e['platform_system'] = 'Linux'
        e['sys_platform'] = 'linux'
        e['os_name'] = 'posix'
        return e
    m.default_environment = mock_env
except Exception:
    pass

from pip._internal.cli.main import main
ret = main([
    'install',
    '-r', 'requirements.txt',
    '--target', 'build',
    '--platform', 'manylinux2014_aarch64',
    '--implementation', 'cp',
    '--python-version', '3.12',
    '--only-binary=:all:',
    '--upgrade'
])
sys.exit(ret)
"
else
    "$PYTHON_CMD" -m pip install -r requirements.txt \
        --target "${BUILD_DIR}" \
        --platform manylinux2014_aarch64 \
        --implementation cp \
        --python-version 3.12 \
        --only-binary=:all: \
        --upgrade
fi

# 3. Copy application source code into build/
echo "[3/5] Copying backend source code to build/..."
mkdir -p "${BUILD_DIR}/vaultrag"
cp -r "${BACKEND_DIR}/src/vaultrag/"* "${BUILD_DIR}/vaultrag/"

# Remove bytecode, caches, and test artifacts
echo "  --> Cleaning bytecode, tests, and temporary artifacts..."
find "${BUILD_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true
find "${BUILD_DIR}" -type f -name "*.pyo" -delete 2>/dev/null || true
find "${BUILD_DIR}" -type d -name "*.dist-info" -exec rm -rf {}/RECORD {}/direct_url.json + 2>/dev/null || true

# 4. Create lambda.zip distribution
echo "[4/5] Archiving package to ${ZIP_FILE}..."
"$PYTHON_CMD" -c "
import os, zipfile
zip_path = 'dist/lambda.zip'
with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for root, dirs, files in os.walk('build'):
        for f in files:
            full = os.path.join(root, f)
            arcname = os.path.relpath(full, 'build')
            zf.write(full, arcname)
"

# 5. Calculate and validate sizes
echo "[5/5] Calculating package metrics..."

# Unzipped and zipped size calculation via python
"$PYTHON_CMD" -c "
import os, sys, hashlib

build_dir = 'build'
zip_file = 'dist/lambda.zip'

total_unzipped_bytes = 0
for root, dirs, files in os.walk(build_dir):
    for f in files:
        fp = os.path.join(root, f)
        if not os.path.islink(fp):
            total_unzipped_bytes += os.path.getsize(fp)

zipped_bytes = os.path.getsize(zip_file)

unzipped_mb = total_unzipped_bytes / (1024 * 1024)
zipped_mb = zipped_bytes / (1024 * 1024)

# Calculate SHA256
h = hashlib.sha256()
with open(zip_file, 'rb') as f:
    while chunk := f.read(65536):
        h.update(chunk)
sha256 = h.hexdigest()

print(f'Unzipped size: {unzipped_mb:.2f} MB ({total_unzipped_bytes} bytes)')
print(f'Zipped size:   {zipped_mb:.2f} MB ({zipped_bytes} bytes)')
print(f'SHA256:        {sha256}')

if unzipped_mb > 240:
    print(f'ERROR: Unzipped package exceeds AWS Lambda limit of 240 MB ({unzipped_mb:.2f} MB > 240 MB)', file=sys.stderr)
    sys.exit(1)

if zipped_mb > 50:
    print(f'[WARN] Zipped package exceeds 50 MB ({zipped_mb:.2f} MB). Must upload via S3 deployment object.', file=sys.stderr)
else:
    print('[OK] Package size is well within AWS Lambda limits.')
"


echo "============================================================"
echo " Packaging completed successfully: ${ZIP_FILE}"
echo "============================================================"
