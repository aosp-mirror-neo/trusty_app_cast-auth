#pragma once
#include <lib/tidl/tidl.h>
class ICastAuth {
public:
    virtual ~ICastAuth() {}
    virtual int ProvisionKey(const ::tidl::Payload& req_payload) = 0;
    virtual int SignHash(const ::tidl::Payload& req_payload,
                         ::tidl::Payload* resp_payload) = 0;
    static constexpr char PORT[] = "com.android.trusty.cast_auth";
    enum : uint32_t {
        REQ_SHIFT = 1,
        RESP_BIT = 1,
        CMD_ProvisionKey = (0 << REQ_SHIFT),
        CMD_SignHash = (1 << REQ_SHIFT),
    };
    struct TIDL_PACKED_ATTR Request_ProvisionKey {
        static constexpr uint32_t num_handles = 0U;
        void send_handles(::tidl::Handle*& ptr) {}
        void recv_handles(::tidl::Handle*& ptr) {}
    };
    struct TIDL_PACKED_ATTR Request_SignHash {
        static constexpr uint32_t num_handles = 0U;
        void send_handles(::tidl::Handle*& ptr) {}
        void recv_handles(::tidl::Handle*& ptr) {}
    };
    virtual void destroy() {}
};
