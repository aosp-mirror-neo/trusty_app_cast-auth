/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TLOG_TAG "cast_auth_client"

#include <assert.h>
#include <lib/tipc/tipc.h>
#include <string.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include <BpCastAuth.h>
#include <lib/tidl/lk_strerror.h>

/**
 * cast_auth_connect()
 * @param cast_auth reference to the proxy instance
 *
 * Return: 0 on success, or an error code < 0 on failure.
 */
int cast_auth_connect(BpCastAuth& cast_auth) {
    int rc;
    rc = cast_auth.connect(ICastAuth::PORT, IPC_CONNECT_WAIT_FOR_PORT);
    if (rc < 0) {
        TLOGE("Failed to connect to %s: %d\n", ICastAuth::PORT, rc);
        return rc;
    }
    return rc;
}

/**
 * cast_auth_ProvisionKey()
 *
 * @param req_payload
 *
 * @return: 0 on success, or an error code < 0 on failure.
 */
extern "C" int cast_auth_ProvisionKey(const ::tidl::Payload& req_payload) {
    int rc;
    BpCastAuth cast_auth;
    rc = cast_auth_connect(cast_auth);
    if (rc < 0) {
        return rc;
    }

    rc = cast_auth.ProvisionKey(req_payload);
    if (rc != NO_ERROR) {
        TLOGE("ProvisionKey failed - %s(%d).\n", lk_strerror(rc), rc);
        return rc;
    }
    return rc;
}

/**
 * cast_auth_SignHash()
 *
 * @param req_payload
 * @param[out] resp_payload
 * @param[out] resp_payload_buf_size: size of the output resp_payload array
 * @param[out] resp_payload_size: number of bytes written into the output array
 *
 * @return: 0 on success, or an error code < 0 on failure.
 */
extern "C" int cast_auth_SignHash(const ::tidl::Payload& req_payload,
                                  uint8_t* resp_payload,
                                  size_t resp_payload_buf_size,
                                  size_t* resp_payload_size) {
    int rc;
    BpCastAuth cast_auth;
    rc = cast_auth_connect(cast_auth);
    if (rc < 0) {
        return rc;
    }

    tidl::Payload resp_payload_payload{
            const_cast<uint8_t*>(resp_payload),
            static_cast<uint32_t>(resp_payload_buf_size)};
    rc = cast_auth.SignHash(req_payload, &resp_payload_payload);
    if (rc != NO_ERROR) {
        TLOGE("SignHash failed - %s(%d).\n", lk_strerror(rc), rc);
        return rc;
    }
    *resp_payload_size = resp_payload_payload.size();
    return rc;
}
