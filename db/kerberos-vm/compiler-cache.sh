#!/bin/sh
# Sourced by the native seed build and the offline package build.
: "${CCACHE_DIR:?missing local compiler cache}" "${CCACHE_REMOTE_STORAGE:?missing file-backed seed}"
for krb_setting in $(env | sed -n 's/^\(CCACHE_[A-Za-z0-9_]*\)=.*/\1/p'); do
    case "$krb_setting" in
        CCACHE_DIR|CCACHE_REMOTE_STORAGE) ;;
        *) unset "$krb_setting" ;;
    esac
done

# GCC delegates compilation to cc1/cc1plus and the assembler. Bind them once
# per build, before adding Debian's ccache compiler symlinks to PATH.
krb_cc1=$(/usr/bin/gcc -print-prog-name=cc1) || return 1
krb_cc1plus=$(/usr/bin/g++ -print-prog-name=cc1plus) || return 1
krb_as=$(/usr/bin/gcc -print-prog-name=as) || return 1
krb_as=$(command -v "$krb_as") || return 1
krb_tools=$(sha256sum /usr/bin/gcc /usr/bin/g++ "$krb_cc1" "$krb_cc1plus" "$krb_as") || return 1
krb_specs=$(/usr/bin/gcc -dumpspecs) || return 1
krb_target=$(/usr/bin/gcc -dumpmachine) || return 1
krb_digest=$(printf '%s\n' "$krb_tools" "$krb_specs" "$krb_target" | sha256sum) || return 1

# Preprocess in each environment so header search and generated headers are
# checked before a cached object can satisfy a compiler call.
export CCACHE_DIR CCACHE_REMOTE_STORAGE CCACHE_CONFIGPATH=/dev/null
export CCACHE_NAMESPACE="krb5-${krb_digest%% *}" CCACHE_COMPILERCHECK=content CCACHE_NODIRECT=1
export PATH="/usr/lib/ccache:$PATH"
unset krb_setting krb_cc1 krb_cc1plus krb_as krb_tools krb_specs krb_target krb_digest
