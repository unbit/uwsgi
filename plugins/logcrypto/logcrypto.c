#include <uwsgi.h>

/*

	this is an UDP logger encrypting each packet with the choosen algo, key and iv.

	It is useful in cloud services without persistent storage for which you want to send logs to an external system.

	Syntax: --logger/--req-logger crypto:addr=<udp_address>,algo=<algorithm>,secret=<key>,iv=<iv>,prefix=<prefix>

	example: 

		uwsgi --plugin logcrypto --logger crypto:addr=127.0.0.1:1717,algo=bf-cbc,secret=ciaociao -M -p 4 -s :3031

*/

extern struct uwsgi_server uwsgi;

struct uwsgi_crypto_logger_conf {
	EVP_CIPHER_CTX *encrypt_ctx;
	char *addr;
	char *algo;
	char *secret;
	char *iv;
	char *prefix;
	size_t prefix_len;
};

static void uwsgi_crypto_logger_setup_encryption(struct uwsgi_crypto_logger_conf *uclc) {

	if (!uwsgi.ssl_initialized) {
                uwsgi_ssl_init();
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        uclc->encrypt_ctx = uwsgi_malloc(sizeof(EVP_CIPHER_CTX));
        EVP_CIPHER_CTX_init(uclc->encrypt_ctx);
#else
        uclc->encrypt_ctx = EVP_CIPHER_CTX_new();
#endif

        const EVP_CIPHER *cipher = EVP_get_cipherbyname(uclc->algo);
        if (!cipher) {
                uwsgi_log_safe("[uwsgi-logcrypto] unable to find algorithm/cipher\n");
		exit(1);
        }
        int cipher_len = EVP_CIPHER_key_length(cipher);

        size_t s_len = strlen(uclc->secret);
        if ((unsigned int) cipher_len > s_len) {
                char *secret_tmp = uwsgi_malloc(cipher_len);
                memcpy(secret_tmp, uclc->secret, s_len);
                memset(secret_tmp + s_len, 0, cipher_len - s_len);
                uclc->secret = secret_tmp;
        }

        int iv_len = EVP_CIPHER_iv_length(cipher);
        size_t s_iv_len = 0;
        if (uclc->iv) {
                s_iv_len = strlen(uclc->iv);
        }
        if ((unsigned int) iv_len > s_iv_len) {
                char *secret_tmp = uwsgi_malloc(iv_len);
                memcpy(secret_tmp, uclc->iv, s_iv_len);
                memset(secret_tmp + s_iv_len, '0', iv_len - s_iv_len);
                uclc->iv = secret_tmp;
        }

        if (EVP_EncryptInit_ex(uclc->encrypt_ctx, cipher, NULL, (const unsigned char *) uclc->secret, (const unsigned char *) uclc->iv) <= 0) {
                uwsgi_error_safe("uwsgi_crypto_logger_setup_encryption()/EVP_EncryptInit_ex()");
                exit(1);
        }

}

static ssize_t uwsgi_crypto_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	struct uwsgi_crypto_logger_conf *uclc = (struct uwsgi_crypto_logger_conf *) ul->data;

	if (!ul->configured) {

		uclc = uwsgi_calloc(sizeof(struct uwsgi_crypto_logger_conf));

		if (uwsgi_kvlist_parse(ul->arg, strlen(ul->arg), ',', '=',
                        "addr", &uclc->addr,
                        "algo", &uclc->algo,
                        "secret", &uclc->secret,
                        "iv", &uclc->iv,
			"prefix", &uclc->prefix,
                NULL)) {
			uwsgi_log_safe("[uwsgi-logcrypto] unable to parse options\n");
			exit(1);
        	}

		if (!uclc->addr || !uclc->algo || !uclc->secret) {
			uwsgi_log_safe("[uwsgi-logcrypto] you have to specify at least addr,algo and secret options\n");
			exit(1);
		}

		if (uclc->prefix) {
			uclc->prefix_len = strlen(uclc->prefix);
		}

        	char *colon = strchr(uclc->addr, ':');
        	if (!colon) {
			uwsgi_log_safe("[uwsgi-logcrypto] invalid UDP address\n");
			exit(1);
		}
                ul->addr_len = socket_to_in_addr(uclc->addr, colon, 0, &ul->addr.sa_in);

        	ul->fd = socket(AF_INET, SOCK_DGRAM, 0);
        	if (ul->fd < 0) {
                	uwsgi_error_safe("uwsgi_crypto_logger()/socket()");
			exit(1);
        	}
		
		uwsgi_crypto_logger_setup_encryption(uclc);

		ul->data = uclc;
		ul->configured = 1;
	}


	struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
	if (uwsgi_buffer_num64(ub, uwsgi_micros())) goto error;
	if (uwsgi_buffer_append(ub, " ", 1)) goto error;
	if (uclc->prefix) {
		if (uwsgi_buffer_append(ub, uclc->prefix, uclc->prefix_len)) goto error;
		if (uwsgi_buffer_append(ub, " ", 1)) goto error;
	}
	if (uwsgi_buffer_append(ub, message, len)) goto error;

	// let's encrypt the message
	unsigned char *encrypted = uwsgi_malloc(ub->pos + EVP_MAX_BLOCK_LENGTH);
        if (EVP_EncryptInit_ex(uclc->encrypt_ctx, NULL, NULL, NULL, NULL) <= 0) {
                uwsgi_error_safe("[uwsgi-logcrypto] EVP_EncryptInit_ex()");
		free(encrypted);
                goto error;
        }

        int e_len = 0;
        if (EVP_EncryptUpdate(uclc->encrypt_ctx, encrypted, &e_len, (unsigned char *) ub->buf, ub->pos) <= 0) {
                uwsgi_error("[uwsgi-logcrypto] EVP_EncryptUpdate()");
		free(encrypted);
                goto error;
        }

        int tmplen = 0;
        if (EVP_EncryptFinal_ex(uclc->encrypt_ctx, encrypted + e_len, &tmplen) <= 0) {
                uwsgi_error("[uwsgi-logcrypto] EVP_EncryptFinal_ex()");
		free(encrypted);
                goto error;
        }

	uwsgi_buffer_destroy(ub);

	ssize_t rlen = sendto(ul->fd, encrypted, e_len + tmplen, 0, (struct sockaddr *) &ul->addr.sa_in, ul->addr_len);
	free(encrypted);
	return rlen;

error:
	uwsgi_buffer_destroy(ub);
	return -1;

}

static void uwsgi_logcrypto_register() {
	uwsgi_register_logger("crypto", uwsgi_crypto_logger);
}

struct uwsgi_plugin logcrypto_plugin = {

        .name = "logcrypto",
        .on_load = uwsgi_logcrypto_register,

};

