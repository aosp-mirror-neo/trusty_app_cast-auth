#include "BnCastAuth.h"
#include <cassert>
#define TLOG_TAG "BnCastAuth"
#include <trusty_log.h>

namespace aidl {
struct __PACKED Request {
  ::trusty::aidl::RequestHeader hdr;
  union __PACKED {
    BnCastAuth::Request_ProvisionKey ProvisionKey;
    BnCastAuth::Request_SignHash SignHash;
  } req;
};
struct __PACKED Response {
  ::trusty::aidl::ResponseHeader hdr;
  union __PACKED {
  } resp;
};
union __PACKED LongestMessage {
  Request req;
  Response resp;
};
BnCastAuth::BnCastAuth(const char *port,
                       const ::trusty::aidl::ipc::Service::PortAcl *acl,
                       uint32_t maximum_payload_size)
    : Service("BnCastAuth", port, sizeof(LongestMessage) + maximum_payload_size,
              acl, &kOps) {}
int BnCastAuth::get_instance(ICastAuth *&instance, const struct uuid *) {
  instance = this;
  return ::android::OK;
}
::trusty::aidl::ipc::Service::Ops BnCastAuth::kOps = {
    .on_connect = BnCastAuth::on_connect,
    .on_message = BnCastAuth::on_message,
    .on_channel_cleanup = BnCastAuth::on_channel_cleanup,
};
int BnCastAuth::on_connect(const ::trusty::aidl::ipc::Service::Port *port,
                           ::trusty::aidl::Handle chan, const struct uuid *peer,
                           void **ctx_p) {
  auto *bn_impl = static_cast<BnCastAuth *>(
      reinterpret_cast<Service *>(const_cast<void *>(port->priv)));
  assert(bn_impl);
  ICastAuth *instance;
  int rc = bn_impl->get_instance(instance, peer);
  if (rc != ::android::OK) {
    return rc;
  }
  *ctx_p = instance;
  return ::android::OK;
}
void BnCastAuth::on_channel_cleanup(void *ctx) {
  auto *impl = reinterpret_cast<ICastAuth *>(ctx);
  assert(impl);
  impl->destroy();
}
int BnCastAuth::on_message(const ::trusty::aidl::ipc::Service::Port *port,
                           ::trusty::aidl::Handle chan, void *ctx) {
  auto *impl = reinterpret_cast<ICastAuth *>(ctx);
  auto *bn_impl = static_cast<BnCastAuth *>(
      reinterpret_cast<Service *>(const_cast<void *>(port->priv)));
  assert(impl);
  assert(bn_impl);
  ::trusty::aidl::Payload req_payload;
  ::trusty::aidl::Payload resp_payload;
  ipc_msg_info_t mi;
  int rc = get_msg(chan, &mi);
  if (rc != ::android::OK) {
    return rc;
  }
  bool call_put_msg = true;
  ::trusty::aidl::RequestHeader req_hdr;
  struct iovec req_hdr_iov = {.iov_base = &req_hdr, .iov_len = sizeof(req_hdr)};
  ipc_msg_t req_hdr_msg = {
      .num_iov = 1, .iov = &req_hdr_iov, .num_handles = 0, .handles = nullptr};
  rc = read_msg(chan, mi.id, 0, &req_hdr_msg);
  if (rc < 0) {
    goto done;
  }
  if (static_cast<size_t>(rc) < sizeof(req_hdr)) {
    rc = ::android::NOT_ENOUGH_DATA;
    goto done;
  }
  switch (req_hdr.cmd) {
  case CMD_ProvisionKey: {
    Request_ProvisionKey req;
    constexpr uint32_t min_msg_len = sizeof(req_hdr) + sizeof(req);
    if (mi.len < min_msg_len) {
      rc = ::android::NOT_ENOUGH_DATA;
      goto send_rc;
    }
    rc = bn_impl->get_payload_buffer(req_payload, mi.len - min_msg_len, false);
    if (rc != ::android::OK) {
      goto send_rc;
    }
    constexpr uint32_t req_num_handles = Request_ProvisionKey::num_handles;
    ::trusty::aidl::Handle req_handles[req_num_handles];
    struct iovec req_iov[] = {
        {.iov_base = &req, .iov_len = sizeof(req)},
        {.iov_base = req_payload.data(), .iov_len = req_payload.size()},
    };
    ipc_msg_t req_msg = {.num_iov = countof(req_iov),
                         .iov = req_iov,
                         .num_handles = req_num_handles,
                         .handles = req_handles};
    rc = read_msg(chan, mi.id, sizeof(req_hdr), &req_msg);
    if (rc < 0) {
      goto done;
    }
    if (static_cast<size_t>(rc) <
        sizeof(req) + static_cast<size_t>(req_payload.size())) {
      rc = ::android::NOT_ENOUGH_DATA;
      goto send_rc;
    }
    put_msg(chan, mi.id);
    call_put_msg = false;
    ::trusty::aidl::Handle *hptr = req_handles;
    req.recv_handles(hptr);
    assert(hptr == &req_handles[req_num_handles]);
    rc = impl->ProvisionKey(req_payload);
    if (rc != ::android::OK) {
      goto send_rc;
    }
    ::trusty::aidl::ResponseHeader resp_hdr = {
        .cmd = req_hdr.cmd | RESP_BIT,
        .rc = rc,
    };
    rc = ::trusty::aidl::ipc::send(chan, &resp_hdr, sizeof(resp_hdr), nullptr,
                                   0);
    if (rc < 0) {
      goto done;
    }
    if (static_cast<size_t>(rc) != sizeof(resp_hdr)) {
      rc = ::android::IO_ERROR;
      goto done;
    }
    break;
  }
  case CMD_SignHash: {
    Request_SignHash req;
    constexpr uint32_t min_msg_len = sizeof(req_hdr) + sizeof(req);
    if (mi.len < min_msg_len) {
      TLOGE("CMD_SignHash NOT_ENOUGH_DATA len(%lu) != min(%u)\n", mi.len,
            min_msg_len);
      rc = ::android::NOT_ENOUGH_DATA;
      goto send_rc;
    }
    rc = bn_impl->get_payload_buffer(req_payload, mi.len - min_msg_len, false);
    if (rc != ::android::OK) {
      goto send_rc;
    }
    rc = bn_impl->get_payload_buffer(resp_payload, req_hdr.resp_payload_size,
                                     true);
    if (rc != ::android::OK) {
      goto send_rc;
    }
    constexpr uint32_t req_num_handles = Request_SignHash::num_handles;
    ::trusty::aidl::Handle req_handles[req_num_handles];
    struct iovec req_iov[] = {
        {.iov_base = &req, .iov_len = sizeof(req)},
        {.iov_base = req_payload.data(), .iov_len = req_payload.size()},
    };
    ipc_msg_t req_msg = {.num_iov = countof(req_iov),
                         .iov = req_iov,
                         .num_handles = req_num_handles,
                         .handles = req_handles};
    rc = read_msg(chan, mi.id, sizeof(req_hdr), &req_msg);
    if (rc < 0) {
      goto done;
    }
    if (static_cast<size_t>(rc) <
        sizeof(req) + static_cast<size_t>(req_payload.size())) {
      rc = ::android::NOT_ENOUGH_DATA;
      goto send_rc;
    }
    put_msg(chan, mi.id);
    call_put_msg = false;
    ::trusty::aidl::Handle *hptr = req_handles;
    req.recv_handles(hptr);
    assert(hptr == &req_handles[req_num_handles]);
    rc = impl->SignHash(req_payload, &resp_payload);
    if (rc != ::android::OK) {
      goto send_rc;
    }
    ::trusty::aidl::ResponseHeader resp_hdr = {
        .cmd = req_hdr.cmd | RESP_BIT,
        .resp_payload_size = resp_payload.size(),
        .rc = rc,
    };
    rc = ::trusty::aidl::ipc::send(chan, &resp_hdr, sizeof(resp_hdr),
                                   resp_payload.data(), resp_payload.size(),
                                   nullptr, 0);
    if (rc < 0) {
      goto done;
    }
    if (static_cast<size_t>(rc) != sizeof(resp_hdr) + resp_payload.size()) {
      rc = ::android::IO_ERROR;
      goto done;
    }
    break;
  }
  default:
    put_msg(chan, mi.id);
    call_put_msg = false;
    rc = ::android::UNKNOWN_TRANSACTION;
    goto send_rc;
    break;
  }
  rc = ::android::OK;
done:
  if (call_put_msg) {
    put_msg(chan, mi.id);
  }
  bn_impl->free_payload_buffer(std::move(req_payload));
  bn_impl->free_payload_buffer(std::move(resp_payload));
  return rc;
send_rc:
  ::trusty::aidl::ResponseHeader resp_hdr = {.cmd = req_hdr.cmd | RESP_BIT,
                                             .rc = rc};
  rc = ::trusty::aidl::ipc::send(chan, &resp_hdr, sizeof(resp_hdr), nullptr, 0);
  if (rc < 0) {
    goto done;
  }
  if (static_cast<size_t>(rc) != sizeof(resp_hdr)) {
    rc = ::android::IO_ERROR;
    goto done;
  }
  goto done;
}
} // namespace aidl
