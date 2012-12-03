#include "../uwsgi.h"
#include <openssl/rand.h>

extern struct uwsgi_server uwsgi;
/*

ssl additional datas are retrieved via indexes.

You can create an index with SSL_CTX_get_ex_new_index and
set data in it with SSL_CTX_set_ex_data

*/

void uwsgi_ssl_init(void) {
        OPENSSL_config(NULL);
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        uwsgi.ssl_initialized = 1;
}

void uwsgi_ssl_info_cb(SSL const *ssl, int where, int ret) {
        if (where & SSL_CB_HANDSHAKE_DONE) {
                if (ssl->s3) {
                        ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
                }
        }
}

int uwsgi_ssl_verify_callback(int ok, X509_STORE_CTX * x509_store) {
        return 1;
}

int uwsgi_ssl_session_new_cb(SSL *ssl, SSL_SESSION *sess) {
        char session_blob[4096];
        int len = i2d_SSL_SESSION(sess, NULL);
        if (len > 4096) {
                if (uwsgi.ssl_verbose) {
                        uwsgi_log("[uwsgi-ssl] unable to store session of size %d\n", len);
                }
                return 0;
        }

        unsigned char *p = (unsigned char *) session_blob;
        i2d_SSL_SESSION(sess, &p);

        // ok let's write the value to the cache
        uwsgi_wlock(uwsgi.cache_lock);
        if (uwsgi_cache_set((char *) sess->session_id, sess->session_id_length, session_blob, len, uwsgi.ssl_sessions_timeout, 0)) {
                if (uwsgi.ssl_verbose) {
                        uwsgi_log("[uwsgi-ssl] unable to store session of size %d in the cache\n", len);
                }
        }
        uwsgi_rwunlock(uwsgi.cache_lock);
        return 0;
}

SSL_SESSION *uwsgi_ssl_session_get_cb(SSL *ssl, unsigned char *key, int keylen, int *copy) {

        uint64_t valsize = 0;

        *copy = 0;
        uwsgi_rlock(uwsgi.cache_lock);
        char *value = uwsgi_cache_get((char *)key, keylen, &valsize);
        if (!value) {
                uwsgi_rwunlock(uwsgi.cache_lock);
                if (uwsgi.ssl_verbose) {
                        uwsgi_log("[uwsgi-ssl] cache miss\n");
                }
                return NULL;
        }
        SSL_SESSION *sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&value, valsize);
        uwsgi_rwunlock(uwsgi.cache_lock);
        return sess;
}

void uwsgi_ssl_session_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess) {
        uwsgi_wlock(uwsgi.cache_lock);
        if (uwsgi_cache_del((char *) sess->session_id, sess->session_id_length, 0, 0)) {
                if (uwsgi.ssl_verbose) {
                        uwsgi_log("[uwsgi-ssl] error removing cache item\n");
                }
        }
        uwsgi_rwunlock(uwsgi.cache_lock);
}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static int uwsgi_sni_cb(SSL *ssl, int *ad, void *arg) {
        const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (!servername) return SSL_TLSEXT_ERR_NOACK;
        size_t servername_len = strlen(servername);

        struct uwsgi_string_list *usl = uwsgi.sni;
        while(usl) {
                if (!uwsgi_strncmp(usl->value, usl->len, (char *)servername, servername_len)) {
                        SSL_set_SSL_CTX(ssl, usl->custom_ptr);
                        return SSL_TLSEXT_ERR_OK;
                }
                usl = usl->next;
        }

#ifdef UWSGI_PCRE
        struct uwsgi_regexp_list *url = uwsgi.sni_regexp;
        while(url) {
                if (uwsgi_regexp_match(url->pattern, url->pattern_extra, (char *)servername, servername_len) >= 0) {
                        SSL_set_SSL_CTX(ssl, url->custom_ptr);
                        return SSL_TLSEXT_ERR_OK;
                }
                url = url->next;
        }
#endif

        return SSL_TLSEXT_ERR_NOACK;
}
#endif

SSL_CTX *uwsgi_ssl_new_server_context(char *name, char *crt, char *key, char *ciphers, char *client_ca) {

        SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
        if (!ctx) {
                uwsgi_log("[uwsgi-ssl] unable to initialize context \"%s\"\n", name);
                return NULL;
        }

        // this part is taken from nginx and stud, removing unneeded functionality
        // stud (for me) has made the best choice on choosing DH approach

        long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
// disable compression (if possibile)
#ifdef SSL_OP_NO_COMPRESSION
        ssloptions |= SSL_OP_NO_COMPRESSION;
#endif

// release/reuse buffers as soon as possibile
#ifdef SSL_MODE_RELEASE_BUFFERS
        SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

        if (SSL_CTX_use_certificate_chain_file(ctx, crt) <= 0) {
                uwsgi_log("[uwsgi-ssl] unable to assign certificate %s for context \"%s\"\n", crt, name);
                SSL_CTX_free(ctx);
                return NULL;
        }

// this part is based from stud
        BIO *bio = BIO_new_file(crt, "r");
        if (bio) {
                DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
                BIO_free(bio);
                if (dh) {
                        SSL_CTX_set_tmp_dh(ctx, dh);
                        DH_free(dh);
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
#ifdef NID_X9_62_prime256v1
                        EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                        SSL_CTX_set_tmp_ecdh(ctx, ecdh);
                        EC_KEY_free(ecdh);
#endif
#endif
#endif
                }
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
                uwsgi_log("[uwsgi-ssl] unable to assign key %s for context \"%s\"\n", key, name);
                SSL_CTX_free(ctx);
                return NULL;
        }


	// if ciphers are specified, prefer server ciphers
        if (ciphers && strlen(ciphers) > 0) {
                if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
                        uwsgi_log("[uwsgi-ssl] unable to set requested ciphers (%s) for context \"%s\"\n", ciphers, name);
                        SSL_CTX_free(ctx);
                        return NULL;
                }

                ssloptions |= SSL_OP_CIPHER_SERVER_PREFERENCE;
        }

        // set session context (if possibile), this is required for client certificate authentication
        if (name) {
                SSL_CTX_set_session_id_context(ctx, (unsigned char *) name, strlen(name));
        }

        if (client_ca) {
                if (client_ca[0] == '!') {
                        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, uwsgi_ssl_verify_callback);
                        client_ca++;
                }
                else {
                        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, uwsgi_ssl_verify_callback);
                }
                // in the future we should allow to set the verify depth
                SSL_CTX_set_verify_depth(ctx, 1);
                if (SSL_CTX_load_verify_locations(ctx, client_ca, NULL) == 0) {
                        uwsgi_log("[uwsgi-ssl] unable to set ssl verify locations (%s) for context \"%s\"\n", client_ca, name);
                        SSL_CTX_free(ctx);
                        return NULL;
                }
                STACK_OF(X509_NAME) * list = SSL_load_client_CA_file(client_ca);
                if (!list) {
                        uwsgi_log("unable to load client CA certificate (%s) for context \"%s\"\n", client_ca, name);
                        SSL_CTX_free(ctx);
                        return NULL;
                }

                SSL_CTX_set_client_CA_list(ctx, list);
        }


        SSL_CTX_set_info_callback(ctx, uwsgi_ssl_info_cb);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        SSL_CTX_set_tlsext_servername_callback(ctx, uwsgi_sni_cb);
#endif

        // disable session caching by default
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (uwsgi.ssl_sessions_use_cache) {

                if (!uwsgi.cache_max_items) {
                        uwsgi_log("you have to enable uWSGI cache to use it as SSL session store !!!\n");
                        exit(1);
                }

                if (uwsgi.cache_blocksize < 4096) {
                        uwsgi_log("cache blocksize for SSL session store must be at least 4096 bytes\n");
                        exit(1);
                }

                SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER|
                        SSL_SESS_CACHE_NO_INTERNAL|
                        SSL_SESS_CACHE_NO_AUTO_CLEAR);

                ssloptions |= SSL_OP_NO_TICKET;

                // just for fun
                SSL_CTX_sess_set_cache_size(ctx, 0);

                // set the callback for ssl sessions
                SSL_CTX_sess_set_new_cb(ctx, uwsgi_ssl_session_new_cb);
                SSL_CTX_sess_set_get_cb(ctx, uwsgi_ssl_session_get_cb);
                SSL_CTX_sess_set_remove_cb(ctx, uwsgi_ssl_session_remove_cb);
        }

        SSL_CTX_set_timeout(ctx, uwsgi.ssl_sessions_timeout);

        SSL_CTX_set_options(ctx, ssloptions);


        return ctx;
}


char *uwsgi_rsa_sign(char *algo_key, char *message, size_t message_len, unsigned int *s_len) {

        // openssl could not be initialized
        if (!uwsgi.ssl_initialized) {
                uwsgi_ssl_init();
        }

        *s_len = 0;
        EVP_PKEY *pk = NULL;

        char *algo = uwsgi_str(algo_key);
        char *colon = strchr(algo, ':');
        if (!colon) {
                uwsgi_log("invalid RSA signature syntax, must be: <digest>:<pemfile>\n");
                free(algo);
                return NULL;
        }

        *colon = 0;
        char *keyfile = colon + 1;
        char *signature = NULL;

        FILE *kf = fopen(keyfile, "r");
        if (!kf) {
                uwsgi_error_open(keyfile);
                free(algo);
                return NULL;
        }

        if (PEM_read_PrivateKey(kf, &pk, NULL, NULL) == 0) {
                uwsgi_log("unable to load private key: %s\n", keyfile);
                free(algo);
                fclose(kf);
                return NULL;
        }

        fclose(kf);

        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        if (!ctx) {
                free(algo);
                EVP_PKEY_free(pk);
                return NULL;
        }

        const EVP_MD *md = EVP_get_digestbyname(algo);
        if (!md) {
                uwsgi_log("unknown digest algo: %s\n", algo);
                free(algo);
                EVP_PKEY_free(pk);
                EVP_MD_CTX_destroy(ctx);
                return NULL;
        }

        *s_len = EVP_PKEY_size(pk);
        signature = uwsgi_malloc(*s_len);

	if (EVP_SignInit_ex(ctx, md, NULL) == 0) {
                ERR_print_errors_fp(stderr);
                free(signature);
                signature = NULL;
                *s_len = 0;
                goto clear;
        }

        if (EVP_SignUpdate(ctx, message, message_len) == 0) {
                ERR_print_errors_fp(stderr);
                free(signature);
                signature = NULL;
                *s_len = 0;
                goto clear;
        }


        if (EVP_SignFinal(ctx, (unsigned char *) signature, s_len, pk) == 0) {
                ERR_print_errors_fp(stderr);
                free(signature);
                signature = NULL;
                *s_len = 0;
                goto clear;
        }

clear:
        free(algo);
        EVP_PKEY_free(pk);
        EVP_MD_CTX_destroy(ctx);
        return signature;

}

char *uwsgi_sanitize_cert_filename(char *base, char *key, uint16_t keylen) {
        uint16_t i;
        char *filename = uwsgi_concat4n(base, strlen(base), "/", 1, key, keylen, ".pem\0", 5);

        for (i = strlen(base) + 1; i < (strlen(base) + 1) + keylen; i++) {
                if (filename[i] >= '0' && filename[i] <= '9')
                        continue;
                if (filename[i] >= 'A' && filename[i] <= 'Z')
                        continue;
                if (filename[i] >= 'a' && filename[i] <= 'z')
                        continue;
                if (filename[i] == '.')
                        continue;
                if (filename[i] == '-')
                        continue;
                if (filename[i] == '_')
                        continue;
                filename[i] = '_';
        }

        return filename;
}

char *uwsgi_ssl_rand(size_t len) {
	unsigned char *buf = uwsgi_calloc(len+1);
	if (RAND_bytes(buf, len) <= 0) {
		return NULL;
	}
	return (char *) buf;
}
