// Local security policy, GPL-3.0-or-later. No fallback to unauthenticated TLS.
#pragma once
#ifdef _WIN32
# include <winsock2.h>
# include <windows.h>
# include <wincrypt.h>
// Windows certificate macros collide with OpenSSL type names.
# undef X509_NAME
# undef X509_EXTENSIONS
# undef PKCS7_SIGNER_INFO
#endif
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

namespace personal {
inline bool configureContext(SSL_CTX *ctx)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) { return false; }
#ifdef _WIN32
    // Read only machine roots, never a PEM file beside the miner or an env override.
    HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"ROOT");
    if (!roots) { return false; }
    PCCERT_CONTEXT item = nullptr;
    unsigned loaded = 0;
    while ((item = CertEnumCertificatesInStore(roots, item)) != nullptr) {
        const unsigned char *der = item->pbCertEncoded;
        X509 *cert = d2i_X509(nullptr, &der, item->cbCertEncoded);
        if (cert) {
            if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert) == 1) { ++loaded; }
            X509_free(cert);
        }
        ERR_clear_error();
    }
    CertCloseStore(roots, 0);
    return loaded > 0;
#else
    return SSL_CTX_set_default_verify_paths(ctx) == 1;
#endif
}
inline bool configurePeer(SSL *ssl, const char *host)
{
    if (!ssl || !host || !*host) { return false; }
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    return SSL_set1_host(ssl, host) == 1 && SSL_set_tlsext_host_name(ssl, host) == 1;
}
}
