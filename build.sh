#!/usr/bin/env bash
# build_levion.sh — Build Levion kernel for OnePlus 9 (lemonade / SM8350)
#
# Usage:
#   ./build_levion.sh                # full build: kernel + vendor_dlkm.img + kernel.zip
#   ./build_levion.sh --vendor_dlkm  # only regenerate vendor_dlkm.img (uses existing out/modules)
#   ./build_levion.sh --image        # only build the kernel Image (no vendor_dlkm, no zip)
#   ./build_levion.sh --obj mm/memory.o   # compile one object (or a folder, e.g. --obj drivers/staging/) and stop
#   ./build_levion.sh --dtbo         # only rebuild dtbo.img and put it in AnyKernel3 (no clean, no zip)
#   ./build_levion.sh -d | --dirty   # skip the clean step, rebuild only what changed (any mode)
#   ./build_levion.sh -fs erofs      # vendor_dlkm.img as EROFS (-fs ext4 is the default)
#
# Expected directory layout (script lives inside the kernel source tree):
#   <parent>/
#   ├── Levion_kernel_OP9/     ← kernel source — script lives here
#   │   └── build_levion.sh
#   ├── vendor_dlkm.img        ← stock image (erofs or ext4, used as base)
#   ├── AnyKernel3/            ← AnyKernel3 dir (cloned from varakumar02/AnyKernel3 op9 if missing)
#   └── toolchains/neutron-clang/  ← auto-imported by this script

set -euo pipefail

# ──────────────────────────────────────────────────────────────
# Paths — derived from script location, nothing hardcoded
# ──────────────────────────────────────────────────────────────

KDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # kernel source root
PARENT="$(dirname "${KDIR}")"                           # one level up
STOCK_IMG="${PARENT}/vendor_dlkm.img"                   # stock image sits in parent
AK3_DIR="${PARENT}/AnyKernel3"                          # AnyKernel3 dir in parent
BUILD_MODULES_DIR="${KDIR}/out/modules"
OUT_VDLKM="${PARENT}/vendor_dlkm_new.img"               # generated image — STOCK_IMG is read-only, never modified

# ──────────────────────────────────────────────────────────────
# Parse args
# Default (no args): full build — kernel + vendor_dlkm.img + zip
# --vendor_dlkm   : only regenerate vendor_dlkm.img
# --image         : only build the kernel Image
# --dtbo          : only rebuild dtbo.img (with AVB footer) into AnyKernel3
# --obj PATH      : compile one object or folder only (quick compile check), no clean
# --debug         : keep the scratch/staging (generated files left on disk)
# -d, --dirty     : skip mrproper, keep out/ and rebuild only what changed
# -fs, --fs TYPE  : vendor_dlkm.img filesystem, ext4 (default) or erofs
# ──────────────────────────────────────────────────────────────

MODE="all"
DEBUG=0
DIRTY=0
FS_TYPE="ext4"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vendor_dlkm) MODE="vendor_dlkm"; shift ;;
        --image)       MODE="image";       shift ;;
        --dtbo)        MODE="dtbo";        shift ;;
        --obj)
            MODE="obj"; OBJ_TARGET="${2:-}"
            [ -n "${OBJ_TARGET}" ] || { echo "--obj needs a path, e.g. --obj mm/memory.o"; exit 1; }
            shift 2 ;;
        --debug)       DEBUG=1;            shift ;;
        -d|--dirty)    DIRTY=1;            shift ;;
        -fs|--fs)
            FS_TYPE="${2:-}"
            [[ "${FS_TYPE}" == "ext4" || "${FS_TYPE}" == "erofs" ]] \
                || { echo "-fs needs ext4 or erofs, got '${FS_TYPE}'"; exit 1; }
            shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ──────────────────────────────────────────────────────────────
# Log + build time — everything printed also goes to
# <parent>/levion_build.log (overwritten each run); the time taken
# is printed at the end, also when the build fails
# ──────────────────────────────────────────────────────────────

LOG="${PARENT}/levion_build.log"
exec > >(tee "${LOG}") 2>&1
SECONDS=0
CLEANUP=""   # scratch dir removed on exit (set by the vendor_dlkm step)
on_exit() {
    local rc=$?
    [ -n "${CLEANUP}" ] && rm -rf "${CLEANUP}"
    [ "${rc}" -ne 0 ] && echo -e "\e[1;31m[✗] Failed after $((SECONDS / 60))m $((SECONDS % 60))s — log: ${LOG}\e[0m"
    return 0
}
trap on_exit EXIT

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

green()  { echo -e "\e[1;32m$*\e[0m"; }
yellow() { echo -e "\e[1;93m$*\e[0m"; }
red()    { echo -e "\e[1;31m$*\e[0m"; }

# ──────────────────────────────────────────────────────────────
# Neutron Clang — auto-imported into <parent>/toolchains/neutron-clang.
# Downloaded when missing or when a newer release is out; reused
# otherwise (also when GitHub can't be reached but a copy exists).
# ──────────────────────────────────────────────────────────────

NEUTRON_REPO="Neutron-Toolchains/clang-build-catalogue"
NEUTRON_DIR="${PARENT}/toolchains/neutron-clang"

setup_neutron_clang() {
    local tag have=""
    [ -f "${NEUTRON_DIR}/.release" ] && have=$(<"${NEUTRON_DIR}/.release")
    tag=$(curl -fsSL "https://api.github.com/repos/${NEUTRON_REPO}/releases/latest" 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null) || tag=""
    if [ -x "${NEUTRON_DIR}/bin/clang" ] && { [ -z "${tag}" ] || [ "${tag}" = "${have}" ]; }; then
        green "[✓] Neutron Clang ${have:-?} already present"
        return 0
    fi
    [ -n "${tag}" ] || { red "[✗] Can't resolve the latest Neutron Clang release and none is installed"; exit 1; }
    yellow "[*] Importing Neutron Clang ${tag}..."
    local stage; stage=$(mktemp -d "${PARENT}/.neutron-clang.XXXXXX")
    curl -fL --retry 3 "https://github.com/${NEUTRON_REPO}/releases/download/${tag}/neutron-clang-${tag}.tar.zst" \
        | tar --zstd -xf - -C "${stage}" --strip-components=1 \
        && "${stage}/bin/clang" --version >/dev/null \
        || { rm -rf "${stage}"; red "[✗] Neutron Clang download failed"; exit 1; }
    echo "${tag}" > "${stage}/.release"
    mkdir -p "$(dirname "${NEUTRON_DIR}")"
    rm -rf "${NEUTRON_DIR}" && mv "${stage}" "${NEUTRON_DIR}"
    green "[✓] Neutron Clang ${tag} → ${NEUTRON_DIR}"
}

if [[ "${MODE}" != "vendor_dlkm" ]]; then
    setup_neutron_clang
    export PATH="${NEUTRON_DIR}/bin:${PATH}"
    green "    $(clang --version | head -1)"
fi

# ──────────────────────────────────────────────────────────────
# AnyKernel3 — cloned next to the kernel (op9 branch, same as CI)
# when the folder is missing
# ──────────────────────────────────────────────────────────────

AK3_REPO="https://github.com/varakumar02/AnyKernel3.git"
AK3_BRANCH="op9"

ensure_ak3() {
    [ -d "${AK3_DIR}" ] && return 0
    yellow "[*] AnyKernel3 not found, cloning ${AK3_REPO} (${AK3_BRANCH}) → ${AK3_DIR}"
    git clone --depth 1 -b "${AK3_BRANCH}" "${AK3_REPO}" "${AK3_DIR}" \
        || { red "[✗] AnyKernel3 clone failed"; exit 1; }
    green "[✓] AnyKernel3 ready"
}

# ──────────────────────────────────────────────────────────────
# Zip signing — ROM releasekey from the priv-keys checkout next to
# the kernel (override the directory with LEVION_KEY_DIR)
# ──────────────────────────────────────────────────────────────

KEY_DIR="${LEVION_KEY_DIR:-${PARENT}/vendor_aox-priv_keys-template}"

# sign_zip <zip> <releasekey.pk8> <releasekey.x509.pem>
# Signs the zip in place with the ROM releasekey (jarsigner, SHA256withRSA)
# and verifies it. The PKCS#12 copy of the key lives in a temp dir that is
# removed afterwards.
sign_zip() {
    local zip="$1" pk8="$2" crt="$3" tmp rc=0
    tmp=$(mktemp -d) && chmod 700 "${tmp}" || return 1
    openssl pkcs8 -inform DER -nocrypt -in "${pk8}" -out "${tmp}/key.pem" \
        && openssl pkcs12 -export -in "${crt}" -inkey "${tmp}/key.pem" -name releasekey \
            -passout pass:levion -out "${tmp}/key.p12" \
        && jarsigner -keystore "${tmp}/key.p12" -storetype PKCS12 -storepass levion \
            -sigalg SHA256withRSA -digestalg SHA-256 "${zip}" releasekey >/dev/null \
        && jarsigner -verify "${zip}" | grep -q "jar verified" || rc=1
    rm -rf "${tmp}"
    return "${rc}"
}

# ──────────────────────────────────────────────────────────────
# dtbo.img → AnyKernel3 with an AVB hash footer (full build and --dtbo)
# ──────────────────────────────────────────────────────────────

place_dtbo() {
    # board overlays (dtbo partition), flashed by anykernel's write_boot
    BUILT_DTBO="${KDIR}/out/arch/arm64/boot/dtbo.img"
    if [ -f "${BUILT_DTBO}" ]; then
        cp -p "${BUILT_DTBO}" "${AK3_DIR}/dtbo.img"
        # AVB hash footer: signed ROMs verify dtbo as a chained partition.
        # Signed with the ROM's AVB key (avb.pk8 in KEY_DIR) when present,
        # unsigned otherwise (an unlocked bootloader accepts that).
        AVB_SIGN=()
        AVB_TMP=""
        if [ -f "${KEY_DIR}/avb.pk8" ]; then
            AVB_TMP=$(mktemp -d) && chmod 700 "${AVB_TMP}"
            openssl pkcs8 -inform DER -nocrypt -in "${KEY_DIR}/avb.pk8" -out "${AVB_TMP}/avb.pem" \
                || { rm -rf "${AVB_TMP}"; red "[✗] could not read ${KEY_DIR}/avb.pk8"; exit 1; }
            AVB_SIGN=(--key "${AVB_TMP}/avb.pem" --algorithm SHA256_RSA4096)
        fi
        python3 "${KDIR}/.github/tools/avbtool.py" add_hash_footer \
            --image "${AK3_DIR}/dtbo.img" --partition_name dtbo \
            --partition_size 25165824 "${AVB_SIGN[@]}" \
            || { rm -rf "${AVB_TMP}"; red "[✗] avbtool failed"; exit 1; }
        [ -n "${AVB_TMP}" ] && rm -rf "${AVB_TMP}"
        if [ ${#AVB_SIGN[@]} -gt 0 ]; then
            green "    Replaced dtbo.img (AVB footer signed with ${KEY_DIR}/avb.pk8)"
        else
            yellow "    Replaced dtbo.img (unsigned AVB footer, no avb.pk8 in ${KEY_DIR})"
        fi
    else
        red "[✗] dtbo.img not found: ${BUILT_DTBO}"
        exit 1
    fi
}

# ──────────────────────────────────────────────────────────────
# Build user/host shown in uname -v and /proc/version — fixed, so
# builds don't carry the local machine's name (override via env)
# ──────────────────────────────────────────────────────────────

export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-varakumar02}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-levion}"

# ──────────────────────────────────────────────────────────────
# Common make flags
# ──────────────────────────────────────────────────────────────

MAKE_FLAGS=(
    O=out
    ARCH=arm64
    LLVM=1
    CC=clang
    LD=ld.lld
    AR=llvm-ar
    NM=llvm-nm
    OBJCOPY=llvm-objcopy
    OBJDUMP=llvm-objdump
    READELF=llvm-readelf
    OBJSIZE=llvm-size
    STRIP=llvm-strip
    CROSS_COMPILE=aarch64-linux-gnu-
    CROSS_COMPILE_ARM32=arm-linux-gnueabi-
)

# ──────────────────────────────────────────────────────────────
# Module presence — vendor_dlkm only makes sense when the kernel
# builds loadable modules. A modules-less kernel (CONFIG_MODULES
# unset → built-in drivers only) has no .ko to pack, so skip the
# whole vendor_dlkm pipeline instead of hard-failing on 0 modules.
# Falls back to "enabled" when no .config exists yet, preserving
# the old behaviour for a bare --vendor_dlkm run before any build.
# ──────────────────────────────────────────────────────────────
modules_enabled() {
    local cfg="${KDIR}/out/.config"
    [ -f "${cfg}" ] || return 0
    grep -qx 'CONFIG_MODULES=y' "${cfg}"
}

# ══════════════════════════════════════════════════════════════
# SINGLE OBJECT  (--obj PATH), then stop
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "obj" ]]; then
    cd "${KDIR}"
    [ -f out/.config ] || make "${MAKE_FLAGS[@]}" vendor/lahaina-qgki_defconfig
    yellow "[*] Compiling ${OBJ_TARGET}..."
    make -j"$(nproc)" "${MAKE_FLAGS[@]}" "${OBJ_TARGET}"
    green "[✓] ${OBJ_TARGET} compiled in $((SECONDS / 60))m $((SECONDS % 60))s"
    exit 0
fi

# ══════════════════════════════════════════════════════════════
# KERNEL BUILD  (skipped for --vendor_dlkm)
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "all" || "${MODE}" == "image" ]]; then

    cd "${KDIR}"

    # Step 1 — Submodules
    yellow "[*] Updating submodules..."
    git submodule update --init --recursive
    green "[✓] Submodules ready"

    # Step 2 — Clean (skipped for --dirty)
    if [ "${DIRTY}" -eq 1 ]; then
        yellow "[*] Dirty build — keeping out/, only changed files rebuild"
    else
        yellow "[*] Cleaning build tree..."
        make "${MAKE_FLAGS[@]}" mrproper || yellow "    [~] mrproper exited non-zero (ignored)"
        git status
        green "[✓] Clean done"
    fi

    # Step 3 — Defconfig
    yellow "[*] Loading defconfig..."
    make "${MAKE_FLAGS[@]}" vendor/lahaina-qgki_defconfig
    green "[✓] Defconfig loaded"

    # Step 4 — Build kernel + modules
    yellow "[*] Building kernel ($(nproc) threads)..."
    make -j"$(nproc)" "${MAKE_FLAGS[@]}"
    green "[✓] Kernel built"

    # Step 5 — Install modules (none on a modules-less kernel)
    if modules_enabled; then
        yellow "[*] Installing modules..."
        cd "${KDIR}/out"
        make modules_install INSTALL_MOD_PATH="${PWD}/modules"
        cd "${KDIR}"
        green "[✓] Modules installed → ${BUILD_MODULES_DIR}"
    fi

fi

# ══════════════════════════════════════════════════════════════
# VENDOR_DLKM.IMG  (skipped for --image)
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "all" || "${MODE}" == "vendor_dlkm" ]] && modules_enabled; then

    yellow "[*] Generating vendor_dlkm.img..."

    if [ ! -f "${STOCK_IMG}" ]; then
        red "[✗] Stock image not found: ${STOCK_IMG}"
        exit 1
    fi

    BUILD_KO_COUNT=$(find "${BUILD_MODULES_DIR}" -type f -name "*.ko" 2>/dev/null | wc -l)
    if [ "${BUILD_KO_COUNT}" -eq 0 ]; then
        red "[✗] No modules in ${BUILD_MODULES_DIR} — build the kernel first (run without --vendor_dlkm)"
        exit 1
    fi
    yellow "[*] Found ${BUILD_KO_COUNT} built modules"

    # Scratch dir — auto-deleted on exit, unless --debug keeps it
    SCRATCH=$(mktemp -d "${KDIR}/.vendor_dlkm_scratch_XXXXXX")
    if [ "${DEBUG}" -eq 0 ]; then
        CLEANUP="${SCRATCH}"
    else
        yellow "    [debug] keeping scratch/staging: ${SCRATCH}"
    fi

    EXTRACT_DIR="${SCRATCH}/extracted"
    mkdir -p "${EXTRACT_DIR}"

    yellow "    Extracting stock image..."
    fsck.erofs --extract="${EXTRACT_DIR}" --overwrite "${STOCK_IMG}" 2>&1

    MODULES_DIR="${EXTRACT_DIR}/lib/modules"

    # Derive exclude / blocklist from stock
    declare -A STOCK_LOAD_SET BLOCKLIST_SET EXCLUDE_SET

    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        STOCK_LOAD_SET["${entry}"]=1
    done < "${MODULES_DIR}/modules.load"

    if [ -f "${MODULES_DIR}/modules.blocklist" ]; then
        while read -r _ mod; do
            [[ -n "${mod}" ]] && BLOCKLIST_SET["${mod}"]=1
        done < <(grep '^blocklist ' "${MODULES_DIR}/modules.blocklist" || true)
    fi

    for ko in "${MODULES_DIR}"/*.ko; do
        mod_name=$(basename "${ko}" .ko)
        if [[ -z "${STOCK_LOAD_SET[${mod_name}]+x}" && -z "${BLOCKLIST_SET[${mod_name}]+x}" ]]; then
            EXCLUDE_SET["${mod_name}"]=1
        fi
    done

    # Replace .ko files
    rm -f "${MODULES_DIR}"/*.ko
    find "${BUILD_MODULES_DIR}" -type f -name "*.ko" -exec cp -p {} "${MODULES_DIR}/" \;

    if [ -f "${MODULES_DIR}/wlan.ko" ]; then
        mv "${MODULES_DIR}/wlan.ko" "${MODULES_DIR}/qca_cld3_wlan.ko"
        yellow "    Renamed wlan.ko → qca_cld3_wlan.ko"
    fi

    NEW_KO_COUNT=$(find "${MODULES_DIR}" -name "*.ko" | wc -l)
    yellow "    ${NEW_KO_COUNT} modules placed"

    # Strip debug symbols
    if command -v llvm-objcopy &>/dev/null; then
        yellow "    Stripping debug symbols..."
        for ko in "${MODULES_DIR}"/*.ko; do
            llvm-objcopy --strip-debug "${ko}"
        done
    fi

    # depmod
    DEPMOD_STAGING="${SCRATCH}/depmod_staging"
    DEPMOD_VER="0.0"
    DEPMOD_MOD_DIR="${DEPMOD_STAGING}/lib/modules/${DEPMOD_VER}"
    mkdir -p "${DEPMOD_MOD_DIR}"

    cp -p "${MODULES_DIR}"/*.ko "${DEPMOD_MOD_DIR}"/
    touch "${DEPMOD_MOD_DIR}/modules.order" \
          "${DEPMOD_MOD_DIR}/modules.builtin" \
          "${DEPMOD_MOD_DIR}/modules.builtin.modinfo"

    depmod -a -b "${DEPMOD_STAGING}" "${DEPMOD_VER}"

    for f in modules.alias modules.dep modules.softdep; do
        [ -f "${DEPMOD_MOD_DIR}/${f}" ] && cp -p "${DEPMOD_MOD_DIR}/${f}" "${MODULES_DIR}/"
    done

    # Fix paths in modules.dep
    sed -i 's|[^ :]*lib/modules/[^/]*/||g' "${MODULES_DIR}/modules.dep"
    sed -i 's|\([a-zA-Z0-9_.-]*\.ko\)|/vendor_dlkm/lib/modules/\1|g' "${MODULES_DIR}/modules.dep"

    # modules.load
    : > "${MODULES_DIR}/modules.load"
    for ko in "${MODULES_DIR}"/*.ko; do
        mod_name=$(basename "${ko}" .ko)
        if [[ -z "${EXCLUDE_SET[${mod_name}]+x}" && -z "${BLOCKLIST_SET[${mod_name}]+x}" ]]; then
            echo "${mod_name}" >> "${MODULES_DIR}/modules.load"
        fi
    done

    # Build the image straight to the output (stock is never touched)
    rm -f "${OUT_VDLKM}"
    if [[ "${FS_TYPE}" == "erofs" ]]; then
        # SELinux file_contexts — must match stock so modules get vendor_file labels
        FILE_CONTEXTS="${SCRATCH}/file_contexts"
        cat <<'EOF' >"${FILE_CONTEXTS}"
/ u:object_r:vendor_file:s0
/vendor_dlkm(/.*)? u:object_r:vendor_file:s0
/vendor_dlkm/etc(/.*)? u:object_r:vendor_configs_file:s0
EOF
        mkfs.erofs \
            --mount-point=/vendor_dlkm \
            --all-root \
            --file-contexts="${FILE_CONTEXTS}" \
            -zlz4 \
            -b4096 \
            -T1230768000 \
            "${OUT_VDLKM}" \
            "${EXTRACT_DIR}" \
            || { red "[✗] mkfs.erofs failed"; exit 1; }
    else
        dd if=/dev/zero of="${OUT_VDLKM}" bs=1M count=512
        mke2fs \
            -O "extent,huge_file" \
            -T largefile \
            -L vendor_dlkm \
            -d "${EXTRACT_DIR}" \
            "${OUT_VDLKM}"
        e2fsck -f -y "${OUT_VDLKM}" || true
        resize2fs -M "${OUT_VDLKM}"
    fi

    # Pad up to the stock partition size if smaller
    ORIG_SIZE=$(stat --format="%s" "${STOCK_IMG}")
    NEW_SIZE=$(stat  --format="%s" "${OUT_VDLKM}")
    if [ "${NEW_SIZE}" -le "${ORIG_SIZE}" ]; then
        truncate -s "${ORIG_SIZE}" "${OUT_VDLKM}"
    else
        red "[!] WARNING: new image (${NEW_SIZE}B) > stock partition (${ORIG_SIZE}B)!"
    fi

    if [[ "${FS_TYPE}" == "erofs" ]]; then
        fsck.erofs "${OUT_VDLKM}" 2>&1 && green "    EROFS fsck passed" || { red "[✗] EROFS fsck failed!"; exit 1; }
    else
        e2fsck -f -n "${OUT_VDLKM}" && green "    ext4 fsck passed" || { red "[✗] ext4 fsck failed!"; exit 1; }
    fi

    green "[✓] vendor_dlkm.img (${FS_TYPE}) written → ${OUT_VDLKM} (stock left untouched)"

fi

# vendor_dlkm was skipped above when the kernel has no modules — say so
if [[ "${MODE}" == "all" || "${MODE}" == "vendor_dlkm" ]] && ! modules_enabled; then
    green "[✓] CONFIG_MODULES not set — modules-less kernel; skipping vendor_dlkm.img"
fi

# ══════════════════════════════════════════════════════════════
# DTBO.IMG ONLY  (--dtbo)
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "dtbo" ]]; then
    cd "${KDIR}"
    yellow "[*] Loading defconfig..."
    make "${MAKE_FLAGS[@]}" vendor/lahaina-qgki_defconfig
    yellow "[*] Building dtbo.img..."
    make -j"$(nproc)" "${MAKE_FLAGS[@]}" dtbo.img
    green "[✓] dtbo.img built"
    ensure_ak3
    place_dtbo
fi

# ══════════════════════════════════════════════════════════════
# KERNEL.ZIP  (only on full build)
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "all" ]]; then

    yellow "[*] Packaging kernel.zip..."

    ensure_ak3

    BUILT_IMAGE="${KDIR}/out/arch/arm64/boot/Image"
    if [ ! -f "${BUILT_IMAGE}" ]; then
        red "[✗] Kernel Image not found: ${BUILT_IMAGE}"
        exit 1
    fi

    # Replace Image
    cp -p "${BUILT_IMAGE}" "${AK3_DIR}/Image"
    green "    Replaced Image"

    place_dtbo

    # Place vendor_dlkm.img (the freshly generated one, NOT the stock base)
    if ! modules_enabled; then
        yellow "    [!] modules-less kernel — no vendor_dlkm.img to place"
    elif [ ! -f "${OUT_VDLKM}" ]; then
        red "[✗] Generated vendor_dlkm not found: ${OUT_VDLKM}"
        exit 1
    else
        cp -p "${OUT_VDLKM}" "${AK3_DIR}/vendor_dlkm.img"
        green "    Placed vendor_dlkm.img"
    fi

    # Replace vendor ramdisk modules — pulled from the SAME prepared staging
    # that built vendor_dlkm (already stripped), so ramdisk and vendor_dlkm
    # carry identical module binaries.
    VR_MODS="${AK3_DIR}/vendor_ramdisk/lib/modules"
    if [ -d "${VR_MODS}" ] && modules_enabled; then
        if [ ! -d "${MODULES_DIR}" ]; then
            red "[✗] vendor_dlkm staging missing (${MODULES_DIR}) — can't source ramdisk modules"
            exit 1
        fi
        yellow "    Replacing vendor ramdisk modules (from vendor_dlkm staging)..."
        rm -f "${VR_MODS}"/*.ko
        RAMDISK_NAMES=(adsp_loader_dlkm apr_dlkm msm_drm q6_notifier_dlkm q6_pdr_dlkm snd_event_dlkm)
        COPIED=0
        for name in "${RAMDISK_NAMES[@]}"; do
            src="${MODULES_DIR}/${name}.ko"
            if [ -f "${src}" ]; then
                cp -p "${src}" "${VR_MODS}/"
                (( COPIED++ )) || true
            else
                yellow "    [!] ${name}.ko not in staging — skipped"
            fi
        done
        green "    Copied ${COPIED}/${#RAMDISK_NAMES[@]} vendor ramdisk modules (already stripped)"
    else
        yellow "    [!] skipping vendor ramdisk modules (modules-less kernel or no AK3 modules dir)"
    fi

    # Zip
    OUT_ZIP="${PARENT}/levion_final.zip"
    rm -f "${OUT_ZIP}"
    cd "${AK3_DIR}"
    # Modules-less kernel: leave the stock vendor_dlkm.img and ramdisk modules
    # out, so anykernel.sh purges the vendor_boot ramdisk's modules.* instead of
    # first-stage init failing to load modules into a kernel without support.
    ZIP_EXCLUDES=(".git/*" ".github/*")
    modules_enabled || ZIP_EXCLUDES+=("vendor_dlkm.img" "vendor_ramdisk/lib/modules/*")
    zip -r9 "${OUT_ZIP}" . -x "${ZIP_EXCLUDES[@]}"
    cd "${KDIR}"

    if [ -f "${KEY_DIR}/releasekey.pk8" ] && [ -f "${KEY_DIR}/releasekey.x509.pem" ]; then
        sign_zip "${OUT_ZIP}" "${KEY_DIR}/releasekey.pk8" "${KEY_DIR}/releasekey.x509.pem" \
            || { red "[✗] Signing failed"; exit 1; }
        green "    Signed with releasekey ($(openssl x509 -in "${KEY_DIR}/releasekey.x509.pem" -noout -fingerprint -sha256 | cut -d= -f2))"
    else
        yellow "    [!] No releasekey in ${KEY_DIR} — zip left unsigned"
    fi

    ZIP_SIZE=$(du -sh "${OUT_ZIP}" | cut -f1)
    green "[✓] kernel.zip → ${OUT_ZIP} (${ZIP_SIZE})"

fi

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────

echo ""
green "[✓] All done in $((SECONDS / 60))m $((SECONDS % 60))s (log: ${LOG})"
[[ "${MODE}" == "all" || "${MODE}" == "image" ]]        && echo "    Kernel Image:     ${KDIR}/out/arch/arm64/boot/Image"
{ [[ "${MODE}" == "all" || "${MODE}" == "vendor_dlkm" ]] && modules_enabled; } && echo "    vendor_dlkm.img:  ${OUT_VDLKM}  (stock base untouched: ${STOCK_IMG})"
[[ "${MODE}" == "all" ]]                                 && echo "    Flashable zip:    ${OUT_ZIP}"
[[ "${MODE}" == "dtbo" ]]                                && echo "    dtbo.img:         ${AK3_DIR}/dtbo.img"
exit 0
