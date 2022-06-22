#pragma once
#include <ICastAuth.h>
class BnCastAuth : public ::tidl::Service, public ICastAuth {
public:
    BnCastAuth() = delete;

protected:
    BnCastAuth(const char*,
               const ::tidl::Service::PortAcl* acl,
               uint32_t maximum_payload_size);
    virtual int get_instance(ICastAuth*&, const struct uuid*);

private:
    static int on_connect(const ::tidl::Service::Port* port,
                          ::tidl::Handle chan,
                          const struct uuid* peer,
                          void** ctx_p);
    static void on_channel_cleanup(void* ctx);
    static int on_message(const ::tidl::Service::Port* port,
                          ::tidl::Handle chan,
                          void* ctx);
    static ::tidl::Service::Ops kOps;
};
