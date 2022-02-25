LOCAL_DIR := $(GET_LOCAL_DIR)
COMMON_DIR := $(LOCAL_DIR)/common

TRUSTY_APP_NAME := cast_auth

CAST_AUTH_USE_PREBUILTS := 1

MODULE := $(LOCAL_DIR)

MODULE_INCLUDES += \
	$(COMMON_DIR) \

MANIFEST := $(LOCAL_DIR)/manifest.json

MODULE_SRCS += \
	$(LOCAL_DIR)/main.cc \
	$(LOCAL_DIR)/cast_auth_impl.cc \

ifeq ($(CAST_AUTH_USE_PREBUILTS),1)

MODULE_INCLUDES += \
	$(LOCAL_DIR)/../aidl/generated \

MODULE_SRCS += \
	$(LOCAL_DIR)/../aidl/generated/BnCastAuth.cpp \

endif

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libstdc++-trusty \
	external/boringssl \
	trusty/user/base/lib/keybox/client \
	trusty/user/base/lib/storage \
	trusty/user/base/lib/system_state \
	trusty/user/base/experimental/lib/binder-paidl \
	trusty/user/base/lib/keybox/client \

ifneq ($(CAST_AUTH_USE_PREBUILTS),1)

MODULE_LIBRARY_DEPS += \
	trusty/user/app/cast-auth/aidl \

endif

include make/trusted_app.mk
