#include "cast_auth_impl.h"

#include <lib/storage/storage.h>
#include <lib/system_state/system_state.h>
#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#define TLOG_TAG "cast-auth-trusty"
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include "lib/keybox/client/keybox.h"

static const char* kKeyPath = "cast_auth_key";
const int RSA_2048_SIZE_BYTES = 256;
const int UNWRAPPED_KEY_MAX_BYTES = 1200;
const int WRAPPING_MAX_BYTES = 1024;
const int WRAPPED_KEY_MAX_BYTES = UNWRAPPED_KEY_MAX_BYTES + WRAPPING_MAX_BYTES;
const int PAYLOAD_MAX_BYTES = WRAPPED_KEY_MAX_BYTES;

bool is_plaintext_rsa_2048_private_key(const ::tidl::Payload& req_payload) {
    bssl::UniquePtr<BIO> bio(
            BIO_new_mem_buf(req_payload.data(), req_payload.size()));
    if (!bio) {
        TLOGE("is_plaintext_rsa_2048_private_key: failed to allocate memory for the "
              "device key\n");
        return ERR_NO_MEMORY;
    }
    bssl::UniquePtr<RSA> rsa(d2i_RSAPrivateKey_bio(bio.get(), NULL));
    return rsa && RSA_size(rsa.get()) == RSA_2048_SIZE_BYTES;
}

class StorageSessionHandle {
public:
    StorageSessionHandle(const char* type) : mSession(STORAGE_INVALID_SESSION) {
        mError = storage_open_session(&mSession, type);
    }
    ~StorageSessionHandle() {
        storage_close_session(mSession);
        mSession = STORAGE_INVALID_SESSION;
    }
    bool valid() { return mSession != STORAGE_INVALID_SESSION; }
    storage_session_t get() { return mSession; }
    int error() { return mError; }

private:
    storage_session_t mSession;
    int mError;
};

CastAuthImpl::CastAuthImpl() : BnCastAuth(PORT, &kAcl, PAYLOAD_MAX_BYTES) {}

int CastAuthImpl::ProvisionKey(const ::tidl::Payload& req_payload) {
    uint8_t unwrapped[UNWRAPPED_KEY_MAX_BYTES];
    size_t unwrapped_size = sizeof(unwrapped);
    if (!system_state_provisioning_allowed()) {
        TLOGE("CastAuthImpl::ProvisionKey: provisioning not allowed\n");
        return ERR_BAD_STATE;
    }
    int rc = NO_ERROR;
    if (is_plaintext_rsa_2048_private_key(req_payload)) {
        if (req_payload.size() > UNWRAPPED_KEY_MAX_BYTES)
            rc = ERR_NOT_ENOUGH_BUFFER;
        else {
            unwrapped_size = req_payload.size();
            memcpy(unwrapped, req_payload.data(), unwrapped_size);
        }
    } else {
        rc = keybox_unwrap(req_payload.data(), req_payload.size(), unwrapped,
                           unwrapped_size, &unwrapped_size);
    }
    if (rc != NO_ERROR) {
        TLOGE("CastAuthImpl::ProvisionKey: failed to unwrap key: %d\n", rc);
        return rc;
    }
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(unwrapped, unwrapped_size));
    if (!bio) {
        TLOGE("CastAuthImpl::ProvisionKey: failed to allocate memory for the "
              "device key\n");
        return ERR_NO_MEMORY;
    }
    bssl::UniquePtr<RSA> rsa(d2i_RSAPrivateKey_bio(bio.get(), NULL));
    if (!rsa || RSA_size(rsa.get()) != RSA_2048_SIZE_BYTES) {
        TLOGE("CastAuthImpl::ProvisionKey: failed to decode device key\n");
        return ERR_NOT_VALID;
    }
    return SaveKey(unwrapped, unwrapped_size);
}

int CastAuthImpl::SignHash(const ::tidl::Payload& req_payload,
                           ::tidl::Payload* resp_payload) {
    uint8_t key[UNWRAPPED_KEY_MAX_BYTES];
    size_t key_size = sizeof(key);
    int rc = LoadKey(key, &key_size);
    if (rc != NO_ERROR) {
        TLOGE("CastAuthImpl::SignHash: failed to load device key: %d\n", rc);
        return rc;
    }
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(key, key_size));
    if (!bio) {
        TLOGE("CastAuthImpl::SignHash: failed to allocate memory for the device "
              "key\n");
        return ERR_NO_MEMORY;
    }
    bssl::UniquePtr<RSA> rsa(d2i_RSAPrivateKey_bio(bio.get(), NULL));
    if (!rsa) {
        TLOGE("CastAuthImpl::SignHash: failed to decode device key\n");
        return ERR_GENERIC;
    }
    if (!RSA_check_key(rsa.get())) {
        TLOGE("CastAuthImpl::SignHash: RSA key failed check\n");
        return ERR_GENERIC;
    }
    size_t expected_size = (size_t)RSA_size(rsa.get());
    if (resp_payload->size() < expected_size) {
        TLOGE("CastAuthImpl::SignHash: response buffer too small\n");
        return ERR_NOT_ENOUGH_BUFFER;
    }
    resp_payload->resize(expected_size);
    rc = RSA_private_encrypt(req_payload.size(), req_payload.data(),
                             resp_payload->data(), rsa.get(),
                             RSA_PKCS1_PADDING);
    if (rc != (int)expected_size) {
        TLOGE("CastAuthImpl::SignHash: RSA_private_encrypt %d \n", rc);
        return ERR_GENERIC;
    }
    return NO_ERROR;
}

int CastAuthImpl::SaveKey(const uint8_t* key, size_t length) {
    if (key == NULL || !length) {
        TLOGE("CastAuthImpl::SaveKey: no keybox provided\n");
        return ERR_GENERIC;
    }
    StorageSessionHandle session(STORAGE_CLIENT_TDP_PORT);
    if (!session.valid()) {
        TLOGE("CastAuthImpl::SaveKey: couldn't open storage session\n");
        return session.error();
    }
    file_handle_t handle;
    int rc = storage_open_file(
            session.get(), &handle, kKeyPath,
            STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE, 0);
    if (rc < 0) {
        TLOGE("CastAuthImpl::SaveKey: failed to open key file: %d\n", rc);
        return rc;
    }
    rc = storage_write(handle, 0, key, length, STORAGE_OP_COMPLETE);
    storage_close_file(handle);
    if (rc < 0) {
        TLOGE("CastAuthImpl::SaveKey: failed to write key: %d\n", rc);
        return rc;
    }
    return NO_ERROR;
}

int CastAuthImpl::LoadKey(uint8_t* key, size_t* length) {
    if (key == NULL || length == NULL) {
        TLOGE("CastAuthImpl::LoadKey: invalid parameters\n");
        return ERR_INVALID_ARGS;
    }
    StorageSessionHandle session(STORAGE_CLIENT_TDP_PORT);
    if (!session.valid()) {
        TLOGE("CastAuthImpl::LoadKey: couldn't open storage session\n");
        return session.error();
    }

    file_handle_t handle;
    int rc = storage_open_file(session.get(), &handle, kKeyPath, 0, 0);
    if (rc < 0) {
        TLOGE("CastAuthImpl::LoadKey: failed to open key file: %d\n", rc);
        return rc;
    }
    storage_off_t keysize;
    rc = storage_get_file_size(handle, &keysize);
    if (rc < 0) {
        TLOGE("CastAuthImpl::LoadKey: couldn't get file size: %d\n", rc);
        storage_close_file(handle);
        return rc;
    }

    if (*length < keysize) {
        TLOGE("CastAuthImpl::LoadKey: output buffer too small, "
              "should be at least %zu bytes\n",
              (size_t)keysize);
        storage_close_file(handle);
        *length = keysize;
        return ERR_NOT_ENOUGH_BUFFER;
    }

    rc = storage_read(handle, 0, key, keysize);
    storage_close_file(handle);
    if (rc < 0) {
        TLOGE("CastAuthImpl::LoadKey: error reading key: %d\n", rc);
        return rc;
    }
    if ((size_t)rc != keysize) {
        TLOGE("CastAuthImpl::LoadKey: error reading key - size (%d) not matching "
              "keysize (%zu)\n",
              rc, (size_t)keysize);
        return ERR_GENERIC;
    }
    *length = keysize;

    return NO_ERROR;
}

int CastAuthImpl::get_payload_buffer(::tidl::Payload& payload,
                                     uint32_t size,
                                     bool) {
    if (size > PAYLOAD_MAX_BYTES) {
        return ERR_NOT_ENOUGH_BUFFER;
    }

    uint8_t* buffer = new uint8_t[PAYLOAD_MAX_BYTES];
    payload = ::tidl::Payload{buffer, size};
    return NO_ERROR;
}

void CastAuthImpl::free_payload_buffer(::tidl::Payload payload) {
    delete[] payload.data();
    // Note that payload is passed by copy, so will be destroyed here, no
    // need to nullify the data member.
}
