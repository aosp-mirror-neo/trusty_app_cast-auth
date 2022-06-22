#pragma once

#include <stdint.h>
#include <trusty_ipc.h>

#include "BnCastAuth.h"

class CastAuthImpl : public BnCastAuth {
public:
  CastAuthImpl();
  int ProvisionKey(const ::tidl::Payload &req_payload) override;
  int SignHash(const ::tidl::Payload &req_payload,
               ::tidl::Payload *resp_payload) override;

private:
  static constexpr struct tipc_port_acl kAcl = {
      .flags = IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT,
      .uuid_num = 0};
  int SaveKey(const uint8_t *key, size_t length);
  int LoadKey(uint8_t *key, size_t *length);
  int get_payload_buffer(::tidl::Payload &payload, uint32_t size,
                         bool) override;
  void free_payload_buffer(::tidl::Payload payload) override;
};
