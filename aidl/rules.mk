LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_AIDLS := \
    $(LOCAL_DIR)/ICastAuth.aidl \

include make/aidl.mk
