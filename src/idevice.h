/*
 * idevice.h
 * Device discovery and communication interface -- header file.
 *
 * Copyright (c) 2008 Zach C. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA 
 */

#ifndef __DEVICE_H
#define __DEVICE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#else
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

#include "common/userpref.h"

#include "libimobiledevice/libimobiledevice.h"

enum connection_type {
	CONNECTION_USBMUXD = 1
};

struct idevice_proto {
	idevice_error_t (*connect)(idevice_t device, uint16_t port, idevice_connection_t *connection);
	idevice_error_t (*free)(idevice_t device);
	idevice_error_t (*get_handle)(idevice_t device, uint32_t *handle);
	idevice_error_t (*get_udid)(idevice_t device, char **udid);
};

struct idevice_connection_proto {
	idevice_error_t (*disconnect)(idevice_connection_t connection);
	idevice_error_t (*send)(idevice_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes);
	idevice_error_t (*receive_timeout)(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout);
	idevice_error_t (*receive)(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes);
	int (*get_fd)(idevice_connection_t connection);
};


struct ssl_data_private {
#ifdef HAVE_OPENSSL
	SSL *session;
	SSL_CTX *ctx;
#else
	gnutls_certificate_credentials_t certificate;
	gnutls_session_t session;
	gnutls_x509_privkey_t root_privkey;
	gnutls_x509_crt_t root_cert;
	gnutls_x509_privkey_t host_privkey;
	gnutls_x509_crt_t host_cert;
#endif
};
typedef struct ssl_data_private *ssl_data_t;

struct idevice_connection_private {
	char *udid;
	struct idevice_connection_proto *proto;
	void *data;
	ssl_data_t ssl_data;
};

struct idevice_private {
	struct idevice_proto *proto;
	void *data;
};

#endif
