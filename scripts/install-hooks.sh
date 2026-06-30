#!/usr/bin/env bash
#
# Instala los git hooks locales del proyecto.
# Ejecutar una vez tras clonar el repositorio.
#
# Uso: bash scripts/install-hooks.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GIT_HOOKS_DIR="$(git -C "${REPO_ROOT}" rev-parse --absolute-git-dir)/hooks"

echo "Instalando git hooks en ${GIT_HOOKS_DIR}..."

cat > "${GIT_HOOKS_DIR}/pre-push" <<'EOF'
#!/usr/bin/env bash
exec "$(git rev-parse --show-toplevel)/scripts/pre-push" "$@"
EOF

chmod +x "${GIT_HOOKS_DIR}/pre-push"

echo "✓ Hook pre-push instalado correctamente."
echo "  - Code sniffer (obligatorio) y PHPUnit se ejecutan antes de cada push."
