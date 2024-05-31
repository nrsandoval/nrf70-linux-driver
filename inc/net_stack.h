/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __NET_STACK_H__
#define __NET_STACK_H__

#include "main.h"
#include "fmac_main.h"

#ifndef CONFIG_NRF700X_RADIO_TEST

struct nrf_wifi_fmac_vif_ctx_lnx *
nrf_wifi_netdev_add_vif(struct nrf_wifi_ctx_lnx *rpu_ctx_lnx,
			const char *if_name, struct wireless_dev *wdev,
			char *mac_addr);

void nrf_wifi_netdev_del_vif(struct net_device *netdev);

void nrf_wifi_netdev_chg_vif(struct net_device *netdev);

void nrf_wifi_netdev_frame_rx_callbk_fn(void *vif_ctx, void *frm);

enum nrf_wifi_status nrf_wifi_netdev_if_state_chg_callbk_fn(
	void *vif_ctx, enum nrf_wifi_fmac_if_carr_state if_state);

#if defined(CONFIG_NRF700X_RAW_DATA_RX) || defined(CONFIG_NRF700X_PROMISC_DATA_RX)
void nrf_wifi_netdev_rx_sniffer_frm(void *os_vif_ctx, void *frm,
	struct raw_rx_pkt_header *raw_rx_hdr,
	bool pkt_free);
#endif /* CONFIG_NRF700X_RAW_DATA_RX || CONFIG_NRF700X_PROMISC_DATA_RX */
#endif /* !CONFIG_NRF700X_RADIO_TEST */
#endif /* __NET_STACK_H__ */
