#pragma once
#include <ICastAuth.h>
class BpCastAuth : public ICastAuth {
public:
    BpCastAuth() : mChan() {}
    int ProvisionKey(const ::tidl::Payload& req_payload) override;
    int SignHash(const ::tidl::Payload& req_payload,
                 ::tidl::Payload* resp_payload) override;
    int connect(const char*, uint32_t);
    bool is_connected();
    void reset();

private:
#if !defined(__QL_TIPC__)
    ::android::base::unique_fd mChan;
#else
    ::tidl::handle mChan;
#endif  // #if !defined(__QL_TIPC__)
};
