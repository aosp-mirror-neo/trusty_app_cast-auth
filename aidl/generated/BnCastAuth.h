#pragma once
#include "ICastAuth.h"
#include <algorithm>
#include <uapi/trusty_uuid.h>
namespace aidl {
class BnCastAuth : public ::trusty::aidl::ipc::Service, public ICastAuth {
public:
  BnCastAuth() = delete;

protected:
  BnCastAuth(const char *, const ::trusty::aidl::ipc::Service::PortAcl *acl,
             uint32_t maximum_payload_size);
  virtual int get_instance(ICastAuth *&, const struct uuid *);

private:
  static int on_connect(const ::trusty::aidl::ipc::Service::Port *port,
                        ::trusty::aidl::Handle chan, const struct uuid *peer,
                        void **ctx_p);
  static void on_channel_cleanup(void *ctx);
  static int on_message(const ::trusty::aidl::ipc::Service::Port *port,
                        ::trusty::aidl::Handle chan, void *ctx);
  static ::trusty::aidl::ipc::Service::Ops kOps;
};
} // namespace aidl
