/* 
 * idevice_usbmux.c
 * Device communication interface to usbmuxd.
 *
 * Copyright (c) 2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2009-2014 Nikias Bassen. All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <usbmuxd.h>
#include "idevice.h"
#include "common/debug.h"

/* idevice_conection (usbmux) */
struct idevice_connection_usbmux_private {
	int sfd;
};

static idevice_error_t idevice_connection_usbmux_disconnect(idevice_connection_t connection)
{
	struct idevice_connection_usbmux_private *data = (struct idevice_connection_usbmux_private *)connection->data;
	usbmuxd_disconnect(data->sfd);
	return IDEVICE_E_SUCCESS;
}

static idevice_error_t idevice_connection_usbmux_send(idevice_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes)
{
	struct idevice_connection_usbmux_private *cdata = (struct idevice_connection_usbmux_private *)connection->data;

	int res = usbmuxd_send(cdata->sfd, data, len, sent_bytes);
	if (res < 0) {
		debug_info("ERROR: usbmuxd_send returned %d (%s)", res, strerror(-res));
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	return IDEVICE_E_SUCCESS;
}

static idevice_error_t idevice_connection_usbmux_receive_timeout(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
{
	struct idevice_connection_usbmux_private *cdata = (struct idevice_connection_usbmux_private *)connection->data;

	int res = usbmuxd_recv_timeout(cdata->sfd, data, len, recv_bytes, timeout);
	if (res < 0) {
		debug_info("ERROR: usbmuxd_recv_timeout returned %d (%s)", res, strerror(-res));
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	return IDEVICE_E_SUCCESS;
}

static idevice_error_t idevice_connection_usbmux_receive(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes)
{
	struct idevice_connection_usbmux_private *cdata = (struct idevice_connection_usbmux_private *)connection->data;

	int res = usbmuxd_recv(cdata->sfd, data, len, recv_bytes);
	if (res < 0) {
		debug_info("ERROR: usbmuxd_recv returned %d (%s)", res, strerror(-res));
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	return IDEVICE_E_SUCCESS;
}

static int idevice_connection_usbmux_get_fd(idevice_connection_t connection)
{
	struct idevice_connection_usbmux_private *cdata = (struct idevice_connection_usbmux_private *)connection->data;
	return cdata->sfd;
}

static struct idevice_connection_proto idevice_usbmux_connection_proto = {
	.disconnect = idevice_connection_usbmux_disconnect,
	.send = idevice_connection_usbmux_send,
	.receive_timeout = idevice_connection_usbmux_receive_timeout,
	.receive = idevice_connection_usbmux_receive,
	.get_fd = idevice_connection_usbmux_get_fd,
};

/* idevice (usbmux) */
struct idevice_usbmux_private {
	char *udid;
	uint32_t muxdev_handle;
};

static idevice_error_t idevice_usbmux_connect(idevice_t device, uint16_t port, idevice_connection_t *connection)
{
	struct idevice_usbmux_private *data = (struct idevice_usbmux_private *)device->data;

	int sfd = usbmuxd_connect(data->muxdev_handle, port);
	if (sfd < 0) {
		debug_info("ERROR: Connecting to usbmuxd failed: %d (%s)", sfd, strerror(-sfd));
		return IDEVICE_E_UNKNOWN_ERROR;
	}

	struct idevice_connection_usbmux_private *cdata = (struct idevice_connection_usbmux_private *)malloc(sizeof(struct idevice_connection_usbmux_private));
	cdata->sfd = sfd;

	idevice_connection_t new_connection = (idevice_connection_t)malloc(sizeof(struct idevice_connection_private));
	idevice_get_udid(device, &new_connection->udid);
	new_connection->proto = &idevice_usbmux_connection_proto;
	new_connection->data = cdata;
	new_connection->ssl_data = NULL;
	*connection = new_connection;
	return IDEVICE_E_SUCCESS;
}

static idevice_error_t idevice_usbmux_free(idevice_t device)
{
	struct idevice_usbmux_private *data = (struct idevice_usbmux_private *)device->data;

	if (data->udid)
		free(data->udid);
	free(data);
	device->data = NULL;
	return IDEVICE_E_SUCCESS;
}

static idevice_error_t idevice_usbmux_get_handle(idevice_t device, uint32_t *handle)
{
	struct idevice_usbmux_private *data = (struct idevice_usbmux_private *)device->data;
	*handle = data->muxdev_handle;
	return IDEVICE_E_SUCCESS;
}

static idevice_error_t idevice_usbmux_get_udid(idevice_t device, const char **udid)
{
	struct idevice_usbmux_private *data = (struct idevice_usbmux_private *)device->data;
	if (!data->udid)
		return IDEVICE_E_INVALID_ARG;
	*udid = data->udid;
	return IDEVICE_E_SUCCESS;
}

static struct idevice_proto idevice_usbmux_proto = {
	.connect = idevice_usbmux_connect,
	.free = idevice_usbmux_free,
	.get_handle = idevice_usbmux_get_handle,
	.get_udid = idevice_usbmux_get_udid,
};

idevice_error_t idevice_usbmux_new(idevice_t *device, const char *udid)
{
	usbmuxd_device_info_t muxdev;
	int res = usbmuxd_get_device_by_udid(udid, &muxdev);
	if (res > 0) {
		struct idevice_usbmux_private *data = (struct idevice_usbmux_private *)malloc(sizeof(struct idevice_usbmux_private));
		data->udid = strdup(muxdev.udid);
		data->muxdev_handle = muxdev.handle;

		idevice_t dev = (idevice_t)malloc(sizeof(struct idevice_private));
		dev->proto = &idevice_usbmux_proto;
		dev->data = data;
		*device = dev;
		return IDEVICE_E_SUCCESS;
	}

	return IDEVICE_E_NO_DEVICE;
}
