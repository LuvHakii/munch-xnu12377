#!/usr/bin/env bash
set -euo pipefail
PROJECT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export THEOS=${THEOS:-$PROJECT/theos}
XNU_ROOT=$(realpath "${1:?Usage: build-local.sh PATCHED_XNU_ROOT [make arguments...]}")
shift
source "$PROJECT/hakios/xnu-env.sh"
export XNU_SRC=$XNU_ROOT
export XNU_SDK_VERSION=26.5
export RC_DARWIN_KERNEL_VERSION=25.5.0
export XNU_SDK_PATH=$PROJECT/out/pac-compat/sdk26.5
PUBLIC_SDK=$THEOS/sdks/iPhoneOS26.5.sdk
SUPPORT_SDK=$XNUDEPS/sdk/iPhoneOS16.5.xnu.sdk
export IIG_SDK_HEADERS=$PROJECT/out/pac-compat/MacOSX26.1.sdk/System/Library/Frameworks/Kernel.framework/Headers

test -d "$PUBLIC_SDK/usr/include"
test -x "$XNUDEPS/host/bin/migcom"
# Keep the working 16.5 SDK read-only; this overlay owns all new build outputs.
mkdir -p "$XNU_SDK_PATH/usr/local/lib/kernel"
for entry in SDKSettings.json SDKSettings.plist Entitlements.plist System Developer; do
    ln -sfn "$PUBLIC_SDK/$entry" "$XNU_SDK_PATH/$entry"
done
for entry in include lib share; do
    ln -sfn "$PUBLIC_SDK/usr/$entry" "$XNU_SDK_PATH/usr/$entry"
done
for entry in include libexec; do
    ln -sfn "$SUPPORT_SDK/usr/local/$entry" "$XNU_SDK_PATH/usr/local/$entry"
done
# The first local link uses the existing support libraries; never rebuild through these links.
for entry in libfirehose_kernel.a libpthread_kext.a; do
    ln -sfn "$SUPPORT_SDK/usr/local/lib/kernel/$entry" "$XNU_SDK_PATH/usr/local/lib/kernel/$entry"
done
HOSTCC="clang -include $XNUDEPS/hostinc/hostcompat.h -I$XNUDEPS/hostinc -Wno-unused-command-line-argument -Wno-error=implicit-function-declaration"
exec make -C "$XNU_SRC" SDKROOT=iphoneos ARCH_CONFIGS=ARM64 MACHINE_CONFIGS=BCM2837 \
    KERNEL_CONFIGS=DEVELOPMENT ARCH_STRING_FOR_CURRENT_MACHINE_CONFIG=arm64 \
    BUILD_WERROR=0 BUILD_LTO=0 DO_CTFMERGE=0 BUILD_DSYM=0 \
    HOST_CC="$HOSTCC" HOST_FLEX=flex HOST_BISON=bison HOST_GM4=m4 \
    CC=xnu-clang CXX=xnu-clang++ LOGCOLORS=n "$@"
