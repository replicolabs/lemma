#!/usr/bin/env bash

set -euo pipefail

LEMMA_VERSION="${LEMMA_VERSION:-latest}"
LEMMA_REPO="replicolabs/lemma"
KB_REPO="replicolabs/kb"
LEMMA_HOME="${HOME}/.lemma"
LEMMA_BIN="${LEMMA_HOME}/bin"
SKILLS_TARBALL_URL="https://github.com/${LEMMA_REPO}/releases/latest/download/skills.tar.gz"
CLAUDE_SKILLS_DIR="${HOME}/.claude/skills"
CODEX_SKILLS_DIR="${HOME}/.codex/skills"

print_step() {
    printf '\n  \033[1;36m→\033[0m %s\n' "$1"
}

print_ok() {
    printf '  \033[1;32m✓\033[0m %s\n' "$1"
}

print_warn() {
    printf '  \033[1;33m!\033[0m %s\n' "$1"
}

print_err() {
    printf '  \033[1;31m✗\033[0m %s\n' "$1" >&2
}

require() {
    if ! command -v "$1" &>/dev/null; then
        print_err "Required tool not found: $1"
        print_err "Please install $1 and try again."
        exit 1
    fi
}

detect_platform() {
    local os arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "${os}" in
        Darwin)
            case "${arch}" in
                arm64)  PLATFORM="aarch64-apple-darwin" ;;
                x86_64) PLATFORM="x86_64-apple-darwin" ;;
                *)
                    print_err "Unsupported macOS architecture: ${arch}"
                    exit 1
                    ;;
            esac
            ;;
        Linux)
            case "${arch}" in
                x86_64)  PLATFORM="x86_64-unknown-linux-musl" ;;
                aarch64) PLATFORM="aarch64-unknown-linux-musl" ;;
                *)
                    print_err "Unsupported Linux architecture: ${arch}"
                    exit 1
                    ;;
            esac
            ;;
        *)
            print_err "Unsupported operating system: ${os}"
            print_err "Windows users: download the binary from https://github.com/${LEMMA_REPO}/releases"
            exit 1
            ;;
    esac
}

download() {
    local url="$1"
    local dest="$2"

    if command -v curl &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -fsSL "${url}" -o "${dest}"
    elif command -v wget &>/dev/null; then
        wget -q "${url}" -O "${dest}"
    else
        print_err "Neither curl nor wget found. Please install one and retry."
        exit 1
    fi
}

get_latest_version() {
    local api_url="https://api.github.com/repos/${LEMMA_REPO}/releases/latest"
    local version

    if command -v curl &>/dev/null; then
        version="$(curl -fsSL "${api_url}" | grep '"tag_name"' | cut -d'"' -f4)"
    else
        version="$(wget -qO- "${api_url}" | grep '"tag_name"' | cut -d'"' -f4)"
    fi

    if [ -z "${version}" ]; then
        print_err "Could not determine latest version. Check your internet connection."
        exit 1
    fi

    echo "${version}"
}

install_binary() {
    print_step "Installing Lemma binary"

    local version
    if [ "${LEMMA_VERSION}" = "latest" ]; then
        version="$(get_latest_version)"
    else
        version="${LEMMA_VERSION}"
    fi

    local binary_url="https://github.com/${LEMMA_REPO}/releases/download/${version}/lemma-${PLATFORM}.tar.gz"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    local tarball="${tmp_dir}/lemma.tar.gz"

    download "${binary_url}" "${tarball}"

    mkdir -p "${LEMMA_BIN}"
    tar -xzf "${tarball}" -C "${tmp_dir}"
    mv "${tmp_dir}/lemma" "${LEMMA_BIN}/lemma"
    chmod +x "${LEMMA_BIN}/lemma"
    rm -rf "${tmp_dir}"

    print_ok "Binary installed to ${LEMMA_BIN}/lemma (version ${version})"
}

install_skills() {
    print_step "Installing Lemma agent skills"

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    local tarball="${tmp_dir}/skills.tar.gz"

    download "${SKILLS_TARBALL_URL}" "${tarball}"
    if [ -d "${HOME}/.claude" ] || command -v claude &>/dev/null; then
        mkdir -p "${CLAUDE_SKILLS_DIR}/lemma"
        tar -xzf "${tarball}" -C "${CLAUDE_SKILLS_DIR}/lemma" --strip-components=1
        print_ok "Skills installed to ${CLAUDE_SKILLS_DIR}/lemma"
    else
        print_warn "Claude Code not detected. Skills not installed for Claude Code."
        print_warn "Install Claude Code at https://claude.ai/code then run: lemma install-skills"
    fi
    if [ -d "${HOME}/.codex" ] || command -v codex &>/dev/null; then
        mkdir -p "${CODEX_SKILLS_DIR}/lemma"
        tar -xzf "${tarball}" -C "${CODEX_SKILLS_DIR}/lemma" --strip-components=1
        print_ok "Skills installed to ${CODEX_SKILLS_DIR}/lemma"
    fi

    rm -rf "${tmp_dir}"
}

add_to_path() {
    print_step "Configuring PATH"

    local path_line="export PATH=\"\${PATH}:${LEMMA_BIN}\""
    local shell_name
    shell_name="$(basename "${SHELL:-/bin/sh}")"

    local profile_file
    case "${shell_name}" in
        bash)  profile_file="${HOME}/.bashrc" ;;
        zsh)   profile_file="${HOME}/.zshrc" ;;
        fish)  profile_file="${HOME}/.config/fish/config.fish"
               path_line="fish_add_path ${LEMMA_BIN}" ;;
        *)     profile_file="${HOME}/.profile" ;;
    esac

    if ! grep -q "${LEMMA_BIN}" "${profile_file}" 2>/dev/null; then
        echo "" >> "${profile_file}"
        echo "# Lemma — Solana security analysis" >> "${profile_file}"
        echo "${path_line}" >> "${profile_file}"
        print_ok "Added ${LEMMA_BIN} to PATH in ${profile_file}"
    else
        print_ok "PATH already configured"
    fi
    export PATH="${PATH}:${LEMMA_BIN}"
}

run_init() {
    print_step "Running lemma init"

    if "${LEMMA_BIN}/lemma" info 2>/dev/null | grep -q "API key: configured"; then
        print_ok "Lemma already initialised"
    else
        "${LEMMA_BIN}/lemma" init
    fi
}

main() {
    printf '\n'
    printf '  \033[1mLemma\033[0m — automated Solana security analysis\n'
    printf '\n'
    require uname
    require tar

    detect_platform
    install_binary
    install_skills
    add_to_path
    run_init

    printf '\n'
    printf '  \033[1;32m✓\033[0m Lemma is installed and ready.\n'
    printf '\n'
    printf '  Open Claude Code in your Solana project and say:\n'
    printf '  \033[36m"analyze my program for security vulnerabilities"\033[0m\n'
    printf '\n'
    printf '  Or use the CLI directly:\n'
    printf '  \033[36mlemma analyze --program ./programs/my_program\033[0m\n'
    printf '\n'
    printf '  Documentation: https://asklemma.xyz\n'
    printf '  Knowledge base: https://github.com/%s\n' "${KB_REPO}"
    printf '\n'
}

main "$@"