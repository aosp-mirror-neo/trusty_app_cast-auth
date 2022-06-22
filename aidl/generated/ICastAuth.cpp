#include <BpCastAuth.h>
int BpCastAuth::ProvisionKey(const ::tidl::Payload& req_payload) {
    if (!mChan.ok()) {
        return ERR_INVALID_ARGS;
    }
    ::tidl::RequestHeader req_hdr = {
            .cmd = CMD_ProvisionKey,
    };
    Request_ProvisionKey req = {};
    constexpr uint32_t req_num_handles =
            ::tidl::HandleOps<Request_ProvisionKey>::num_handles;
    ::tidl::Handle req_handles[req_num_handles];
    ::tidl::Handle* hptr = req_handles;
    req.send_handles(hptr);
    assert(hptr == &req_handles[req_num_handles]);
    int rc =
            ::tidl::ipc::send(mChan.get(), &req_hdr, sizeof(req_hdr), &req,
                              sizeof(req), req_payload.data(),
                              req_payload.size(), req_handles, req_num_handles);
    if (rc < 0) {
        return rc;
    }
    if (static_cast<size_t>(rc) !=
        sizeof(req_hdr) + sizeof(req) +
                static_cast<size_t>(req_payload.size())) {
        return ERR_BAD_LEN;
    }
    rc = ::tidl::ipc::wait_for_msg(mChan.get());
    if (rc != NO_ERROR) {
        return rc;
    }
    ::tidl::ResponseHeader resp_hdr;
    rc = ::tidl::ipc::recv(mChan.get(), sizeof(resp_hdr), &resp_hdr,
                           sizeof(resp_hdr), nullptr, 0);
    if (rc < 0) {
        return rc;
    }
    if (static_cast<size_t>(rc) < sizeof(resp_hdr)) {
        return ERR_BAD_LEN;
    }
    if (resp_hdr.cmd != (CMD_ProvisionKey | RESP_BIT)) {
        return ERR_CMD_UNKNOWN;
    }
    if (resp_hdr.rc != NO_ERROR) {
        if (static_cast<size_t>(rc) != sizeof(resp_hdr)) {
            return ERR_BAD_LEN;
        }
        return resp_hdr.rc;
    }
    if (static_cast<size_t>(rc) != sizeof(resp_hdr)) {
        return ERR_BAD_LEN;
    }
    return NO_ERROR;
}
int BpCastAuth::SignHash(const ::tidl::Payload& req_payload,
                         ::tidl::Payload* resp_payload) {
    if (!mChan.ok()) {
        return ERR_INVALID_ARGS;
    }
    ::tidl::RequestHeader req_hdr = {
            .cmd = CMD_SignHash,
            .resp_payload_size = resp_payload->size(),
    };
    Request_SignHash req = {};
    constexpr uint32_t req_num_handles =
            ::tidl::HandleOps<Request_SignHash>::num_handles;
    ::tidl::Handle req_handles[req_num_handles];
    ::tidl::Handle* hptr = req_handles;
    req.send_handles(hptr);
    assert(hptr == &req_handles[req_num_handles]);
    int rc =
            ::tidl::ipc::send(mChan.get(), &req_hdr, sizeof(req_hdr), &req,
                              sizeof(req), req_payload.data(),
                              req_payload.size(), req_handles, req_num_handles);
    if (rc < 0) {
        return rc;
    }
    if (static_cast<size_t>(rc) !=
        sizeof(req_hdr) + sizeof(req) +
                static_cast<size_t>(req_payload.size())) {
        return ERR_BAD_LEN;
    }
    rc = ::tidl::ipc::wait_for_msg(mChan.get());
    if (rc != NO_ERROR) {
        return rc;
    }
    ::tidl::ResponseHeader resp_hdr;
    rc = ::tidl::ipc::recv(mChan.get(), sizeof(resp_hdr), &resp_hdr,
                           sizeof(resp_hdr), resp_payload->data(),
                           resp_payload->size(), nullptr, 0);
    if (rc < 0) {
        return rc;
    }
    if (static_cast<size_t>(rc) < sizeof(resp_hdr)) {
        return ERR_BAD_LEN;
    }
    if (resp_hdr.cmd != (CMD_SignHash | RESP_BIT)) {
        return ERR_CMD_UNKNOWN;
    }
    if (resp_hdr.rc != NO_ERROR) {
        if (static_cast<size_t>(rc) != sizeof(resp_hdr)) {
            return ERR_BAD_LEN;
        }
        return resp_hdr.rc;
    }
    if (static_cast<size_t>(rc) !=
        sizeof(resp_hdr) + static_cast<size_t>(resp_hdr.resp_payload_size)) {
        return ERR_BAD_LEN;
    }
    resp_payload->resize(resp_hdr.resp_payload_size);
    return NO_ERROR;
}
int BpCastAuth::connect(const char* port, uint32_t flags) {
    if (mChan.ok()) {
        return ERR_INVALID_ARGS;
    }
    return ::tidl::ipc::connect(port, flags, mChan);
}

bool BpCastAuth::is_connected() {
    return (mChan.ok());
}
void BpCastAuth::reset() {
    mChan.reset();
}
#if !defined(__QL_TIPC__)
#include <BnCastAuth.h>
struct TIDL_PACKED_ATTR Request {
    ::tidl::RequestHeader hdr;
    union TIDL_PACKED_ATTR {
        BnCastAuth::Request_ProvisionKey ProvisionKey;
        BnCastAuth::Request_SignHash SignHash;
    } req;
};
struct TIDL_PACKED_ATTR Response {
    ::tidl::ResponseHeader hdr;
    union TIDL_PACKED_ATTR {
    } resp;
};
union TIDL_PACKED_ATTR LongestMessage {
    Request req;
    Response resp;
};
BnCastAuth::BnCastAuth(const char* port,
                       const ::tidl::Service::PortAcl* acl,
                       uint32_t maximum_payload_size)
        : Service("BnCastAuth",
                  port,
                  sizeof(LongestMessage) + maximum_payload_size,
                  acl,
                  &kOps) {}
int BnCastAuth::get_instance(ICastAuth*& instance, const struct uuid*) {
    instance = this;
    return NO_ERROR;
}
::tidl::Service::Ops BnCastAuth::kOps = {
        .on_connect = BnCastAuth::on_connect,
        .on_message = BnCastAuth::on_message,
        .on_channel_cleanup = BnCastAuth::on_channel_cleanup,
};
int BnCastAuth::on_connect(const ::tidl::Service::Port* port,
                           ::tidl::Handle chan,
                           const struct uuid* peer,
                           void** ctx_p) {
    auto* bn_impl = static_cast<BnCastAuth*>(
            reinterpret_cast<Service*>(const_cast<void*>(port->priv)));
    assert(bn_impl);
    ICastAuth* instance;
    int rc = bn_impl->get_instance(instance, peer);
    if (rc != NO_ERROR) {
        return rc;
    }
    *ctx_p = instance;
    return NO_ERROR;
}
void BnCastAuth::on_channel_cleanup(void* ctx) {
    auto* impl = reinterpret_cast<ICastAuth*>(ctx);
    assert(impl);
    impl->destroy();
}
int BnCastAuth::on_message(const ::tidl::Service::Port* port,
                           ::tidl::Handle chan,
                           void* ctx) {
    auto* impl = reinterpret_cast<ICastAuth*>(ctx);
    auto* bn_impl = static_cast<BnCastAuth*>(
            reinterpret_cast<Service*>(const_cast<void*>(port->priv)));
    assert(impl);
    assert(bn_impl);
    ::tidl::Payload req_payload;
    ::tidl::Payload resp_payload;
    ipc_msg_info_t mi;
    int rc = get_msg(chan, &mi);
    if (rc != NO_ERROR) {
        return rc;
    }
    bool call_put_msg = true;
    ::tidl::RequestHeader req_hdr;
    struct iovec req_hdr_iov = {.iov_base = &req_hdr,
                                .iov_len = sizeof(req_hdr)};
    ipc_msg_t req_hdr_msg = {.num_iov = 1,
                             .iov = &req_hdr_iov,
                             .num_handles = 0,
                             .handles = nullptr};
    rc = read_msg(chan, mi.id, 0, &req_hdr_msg);
    if (rc < 0) {
        goto done;
    }
    if (static_cast<size_t>(rc) < sizeof(req_hdr)) {
        rc = ERR_BAD_LEN;
        goto done;
    }
    switch (req_hdr.cmd) {
    case CMD_ProvisionKey: {
        Request_ProvisionKey req;
        constexpr uint32_t min_msg_len = sizeof(req_hdr) + sizeof(req);
        if (mi.len < min_msg_len) {
            rc = ERR_BAD_LEN;
            goto send_rc;
        }
        rc = bn_impl->get_payload_buffer(req_payload, mi.len - min_msg_len,
                                         false);
        if (rc != NO_ERROR) {
            goto send_rc;
        }
        constexpr uint32_t req_num_handles = Request_ProvisionKey::num_handles;
        ::tidl::Handle req_handles[req_num_handles];
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
            rc = ERR_BAD_LEN;
            goto send_rc;
        }
        put_msg(chan, mi.id);
        call_put_msg = false;
        ::tidl::Handle* hptr = req_handles;
        req.recv_handles(hptr);
        assert(hptr == &req_handles[req_num_handles]);
        rc = impl->ProvisionKey(req_payload);
        if (rc != NO_ERROR) {
            goto send_rc;
        }
        ::tidl::ResponseHeader resp_hdr = {
                .cmd = req_hdr.cmd | RESP_BIT,
                .rc = rc,
        };
        rc = ::tidl::ipc::send(chan, &resp_hdr, sizeof(resp_hdr), nullptr, 0);
        if (rc < 0) {
            goto done;
        }
        if (static_cast<size_t>(rc) != sizeof(resp_hdr)) {
            rc = ERR_BAD_LEN;
            goto done;
        }
        break;
    }
    case CMD_SignHash: {
        Request_SignHash req;
        constexpr uint32_t min_msg_len = sizeof(req_hdr) + sizeof(req);
        if (mi.len < min_msg_len) {
            rc = ERR_BAD_LEN;
            goto send_rc;
        }
        rc = bn_impl->get_payload_buffer(req_payload, mi.len - min_msg_len,
                                         false);
        if (rc != NO_ERROR) {
            goto send_rc;
        }
        rc = bn_impl->get_payload_buffer(resp_payload,
                                         req_hdr.resp_payload_size, true);
        if (rc != NO_ERROR) {
            goto send_rc;
        }
        constexpr uint32_t req_num_handles = Request_SignHash::num_handles;
        ::tidl::Handle req_handles[req_num_handles];
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
            rc = ERR_BAD_LEN;
            goto send_rc;
        }
        put_msg(chan, mi.id);
        call_put_msg = false;
        ::tidl::Handle* hptr = req_handles;
        req.recv_handles(hptr);
        assert(hptr == &req_handles[req_num_handles]);
        rc = impl->SignHash(req_payload, &resp_payload);
        if (rc != NO_ERROR) {
            goto send_rc;
        }
        ::tidl::ResponseHeader resp_hdr = {
                .cmd = req_hdr.cmd | RESP_BIT,
                .resp_payload_size = resp_payload.size(),
                .rc = rc,
        };
        rc = ::tidl::ipc::send(chan, &resp_hdr, sizeof(resp_hdr),
                               resp_payload.data(), resp_payload.size(),
                               nullptr, 0);
        if (rc < 0) {
            goto done;
        }
        if (static_cast<size_t>(rc) != sizeof(resp_hdr) + resp_payload.size()) {
            rc = ERR_BAD_LEN;
            goto done;
        }
        break;
    }
    default:
        put_msg(chan, mi.id);
        call_put_msg = false;
        rc = ERR_CMD_UNKNOWN;
        goto send_rc;
        break;
    }
    rc = NO_ERROR;
done:
    if (call_put_msg) {
        put_msg(chan, mi.id);
    }
    bn_impl->free_payload_buffer(tidl::move(req_payload));
    bn_impl->free_payload_buffer(tidl::move(resp_payload));
    return rc;
send_rc:
    ::tidl::ResponseHeader resp_hdr = {.cmd = req_hdr.cmd | RESP_BIT, .rc = rc};
    rc = ::tidl::ipc::send(chan, &resp_hdr, sizeof(resp_hdr), nullptr, 0);
    if (rc < 0) {
        goto done;
    }
    if (static_cast<size_t>(rc) != sizeof(resp_hdr)) {
        rc = ERR_BAD_LEN;
        goto done;
    }
    goto done;
}
#endif  // #if !defined(__QL_TIPC__)
