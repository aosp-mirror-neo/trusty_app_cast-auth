#pragma once

#include <stdint.h>
#include <trusty_ipc.h>

#include "BnCastAuth.h"

class CastAuthImpl : public aidl::BnCastAuth {
public:
  CastAuthImpl();
  int ProvisionKey(const ::trusty::aidl::Payload &req_payload) override;
  int SignHash(const ::trusty::aidl::Payload &req_payload,
               ::trusty::aidl::Payload *resp_payload) override;

private:
  static constexpr struct tipc_port_acl kAcl = {
      .flags = IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT,
      .uuid_num = 0};
  int SaveKey(const uint8_t *key, size_t length);
  int LoadKey(uint8_t *key, size_t *length);
  int get_payload_buffer(::trusty::aidl::Payload &payload, uint32_t size,
                         bool) override;
  void free_payload_buffer(::trusty::aidl::Payload payload) override;
};
