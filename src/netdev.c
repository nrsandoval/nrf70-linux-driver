#ifndef CONFIG_NRF700X_RADIO_TEST
/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <net/cfg80211.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <uapi/linux/if_arp.h>

#include "host_rpu_umac_if.h"
#include "main.h"
#include "fmac_main.h"
#include "fmac_api.h"
#include "fmac_util.h"
#include "fmac_peer.h"
#include "shim.h"
#include "queue.h"

#ifdef CONFIG_NRF700X_DATA_TX

static void nrf_cfg80211_data_tx_routine(struct work_struct *w)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx =
		container_of(w, struct nrf_wifi_fmac_vif_ctx_lnx, ws_data_tx);
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx = NULL;
	enum nrf_wifi_status status = NRF_WIFI_STATUS_FAIL;
	void *netbuf = NULL;
#if CONFIG_NRF700X_RAW_DATA_TX
	struct nrf_wifi_fmac_dev_ctx_def *def_dev_ctx = NULL;
	unsigned char *ra = NULL;
#endif

	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
	fmac_dev_ctx = rpu_ctx_lnx->rpu_ctx;
#if CONFIG_NRF700X_RAW_DATA_TX
	def_dev_ctx = wifi_dev_priv(fmac_dev_ctx);
#endif

	netbuf = nrf_wifi_utils_q_dequeue(fmac_dev_ctx->fpriv->opriv,
					  vif_ctx_lnx->data_txq);
	if (netbuf == NULL) {
		pr_err("%s: fail to get tx data from queue\n", __func__);
		return;
	}

	// check if we are sending normal or raw
#if CONFIG_NRF700X_RAW_DATA_TX
	ra = nrf_wifi_util_get_ra(def_dev_ctx->vif_ctx[vif_ctx_lnx->if_idx], netbuf);
	if (-1 == nrf_wifi_fmac_peer_get_id(fmac_dev_ctx, ra)) {
		status = nrf_wifi_fmac_start_rawpkt_xmit(rpu_ctx_lnx->rpu_ctx,
							vif_ctx_lnx->if_idx, skb_raw_pkt_to_nbuf(netbuf));
	} else {
#endif
		if ((vif_ctx_lnx->if_carr_state != NRF_WIFI_FMAC_IF_CARR_STATE_ON)) {
				return;
			}
		status = nrf_wifi_fmac_start_xmit(rpu_ctx_lnx->rpu_ctx,
						  vif_ctx_lnx->if_idx, netbuf);
#if CONFIG_NRF700X_RAW_DATA_TX
	}
#endif
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_start_xmit failed\n", __func__);
	}

	if (nrf_wifi_utils_q_len(fmac_dev_ctx->fpriv->opriv,
				 vif_ctx_lnx->data_txq) > 0) {
		schedule_work(&vif_ctx_lnx->ws_data_tx);
	}
}

static void nrf_cfg80211_queue_monitor_routine(struct work_struct *w)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = container_of(
		w, struct nrf_wifi_fmac_vif_ctx_lnx, ws_queue_monitor);
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx = NULL;
	struct nrf_wifi_fmac_dev_ctx_def *def_dev_ctx = NULL;
	struct rpu_host_stats *host_stats = NULL;

	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
	fmac_dev_ctx = rpu_ctx_lnx->rpu_ctx;
	def_dev_ctx = wifi_dev_priv(fmac_dev_ctx);
	host_stats = &def_dev_ctx->host_stats;

	if (vif_ctx_lnx->num_tx_pkt - host_stats->total_tx_pkts <=
	    CONFIG_NRF700X_MAX_TX_PENDING_QLEN / 2) {
		if (netif_queue_stopped(vif_ctx_lnx->netdev)) {
			netif_wake_queue(vif_ctx_lnx->netdev);
		}
	} else {
		schedule_work(&vif_ctx_lnx->ws_queue_monitor);
	}
}

netdev_tx_t nrf_wifi_netdev_start_xmit(struct sk_buff *skb,
				       struct net_device *netdev)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx = NULL;
	struct nrf_wifi_fmac_dev_ctx_def *def_dev_ctx = NULL;
	struct rpu_host_stats *host_stats = NULL;
	int status = -1;
	int ret = NETDEV_TX_OK;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	fmac_dev_ctx = rpu_ctx_lnx->rpu_ctx;

	def_dev_ctx = wifi_dev_priv(fmac_dev_ctx);
	host_stats = &def_dev_ctx->host_stats;

	if (skb->dev != netdev) {
		pr_err("%s: wrong net dev\n", __func__);
		goto out;
	}

	if ((vif_ctx_lnx->num_tx_pkt - host_stats->total_tx_pkts) >=
	    CONFIG_NRF700X_MAX_TX_PENDING_QLEN) {
		if (!netif_queue_stopped(netdev)) {
			netif_stop_queue(netdev);
		}
		schedule_work(&vif_ctx_lnx->ws_queue_monitor);
	}

	status = nrf_wifi_utils_q_enqueue(fmac_dev_ctx->fpriv->opriv,
					  vif_ctx_lnx->data_txq, skb);

	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_utils_q_enqueue failed\n", __func__);
		ret = NETDEV_TX_BUSY;
		return ret;
	}

	vif_ctx_lnx->num_tx_pkt++;
	schedule_work(&vif_ctx_lnx->ws_data_tx);

out:
	return ret;
}
#endif

static void nrf_wifi_ethtool_get_drvinfo(struct net_device *net_device,
										struct ethtool_drvinfo *info)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	unsigned int fw_ver = 0;
	enum nrf_wifi_status status = NRF_WIFI_STATUS_FAIL;

	vif_ctx_lnx = netdev_priv(net_device);

	strscpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strscpy(info->version, NRF_WIFI_FMAC_DRV_VER, sizeof(info->version));

	status = nrf_wifi_fmac_ver_get(vif_ctx_lnx->rpu_ctx->rpu_ctx, &fw_ver);

	if (status == NRF_WIFI_STATUS_SUCCESS) {
		snprintf(info->fw_version, sizeof(info->fw_version), "%d.%d.%d.%d", 
			NRF_WIFI_UMAC_VER(fw_ver), NRF_WIFI_UMAC_VER_MAJ(fw_ver),
			NRF_WIFI_UMAC_VER_MIN(fw_ver), NRF_WIFI_UMAC_VER_EXTRA(fw_ver));
	}
}

static const struct ethtool_ops nrf_wifi_ethtool_ops = {
	.get_drvinfo = nrf_wifi_ethtool_get_drvinfo
};

int nrf_wifi_netdev_open(struct net_device *netdev)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_chg_vif_state_info *vif_info = NULL;
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_fmac_reg_info reg_domain_info = {0};
	enum wifi_operation_modes mode = NRF_WIFI_STA_MODE;
	int status = -1;

	pr_info("%s: open\n", __func__);

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	netdev->ethtool_ops = &nrf_wifi_ethtool_ops;
	wdev = netdev->ieee80211_ptr;

#if 0
	if (wdev->iftype == NL80211_IFTYPE_AP) {
		status = 0;
		goto out;
	}
#endif

	vif_info = kzalloc(sizeof(*vif_info), GFP_KERNEL);

	if (!vif_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	vif_info->state = 1;

	vif_info->if_index = vif_ctx_lnx->if_idx;

	status = nrf_wifi_fmac_chg_vif_state(rpu_ctx_lnx->rpu_ctx,
					     vif_ctx_lnx->if_idx, vif_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_chg_vif_state failed\n", __func__);
		goto out;
	}

	reg_domain_info.alpha2[0] = '0';
	reg_domain_info.alpha2[1] = '0';
	reg_domain_info.force = false;

	status = nrf_wifi_fmac_set_reg(rpu_ctx_lnx->rpu_ctx, &reg_domain_info);
	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_reg failed\n", __func__);
		goto out;
	}

	if (wdev->iftype == NL80211_IFTYPE_MONITOR) {
// TODO Tx injection doesn't seem to work as intended at the moment
#if CONFIG_NRF700X_RAW_DATA_TX
		mode = NRF_WIFI_MONITOR_MODE | NRF_WIFI_TX_INJECTION_MODE;
#else
		mode = NRF_WIFI_MONITOR_MODE;
#endif
	} else if (wdev->iftype == NL80211_IFTYPE_AP) {
		pr_info("%s: ap mode\n", __func__);
		mode = NRF_WIFI_AP_MODE;
	} else {
		mode = NRF_WIFI_STA_MODE;
	}

	status = nrf_wifi_fmac_set_mode(rpu_ctx_lnx->rpu_ctx,
								vif_ctx_lnx->if_idx,
								mode);
	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_fmac_set_mode failed\n", __func__);
		goto out;
	}

	status = nrf_wifi_fmac_set_packet_filter(rpu_ctx_lnx->rpu_ctx, NRF_WIFI_PACKET_FILTER_ALL,
										vif_ctx_lnx->if_idx, 255);
	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_packet_filter failed\n", __func__);
	}

out:
	if (vif_info)
		kfree(vif_info);

	return status;
}

int nrf_wifi_netdev_close(struct net_device *netdev)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_chg_vif_state_info *vif_info = NULL;
	int status = -1;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	vif_info = kzalloc(sizeof(*vif_info), GFP_KERNEL);

	if (!vif_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	vif_info->state = 0;

	vif_info->if_index = vif_ctx_lnx->if_idx;

	status = nrf_wifi_fmac_chg_vif_state(rpu_ctx_lnx->rpu_ctx,
					     vif_ctx_lnx->if_idx, vif_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_chg_vif_state failed\n", __func__);
		goto out;
	}
	flush_work(&vif_ctx_lnx->ws_data_tx);
	flush_work(&vif_ctx_lnx->ws_queue_monitor);

	netif_carrier_off(netdev);
out:
	pr_info("%s: Closed\n", __func__);
	if (vif_info)
		kfree(vif_info);

	return status;
}

int nrf_wifi_set_mac_address(struct net_device *netdev, void *p)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct sockaddr *addr = (struct sockaddr *)p;
	unsigned char mac_addr[ETH_ALEN];
	int status = -1;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	ether_addr_copy(mac_addr, addr->sa_data);

	status = nrf_wifi_fmac_set_vif_macaddr(rpu_ctx_lnx->rpu_ctx,
		vif_ctx_lnx->if_idx, mac_addr);
	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_vif_macaddr failed\n", __func__);
	}

	ether_addr_copy(netdev->dev_addr, mac_addr);

	return status;
}

void nrf_wifi_netdev_set_multicast_list(struct net_device *netdev)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_mcast_cfg *mcast_info = NULL;
	int status = -1;
	struct netdev_hw_addr *ha = NULL;
	int indx = 0, count = 0;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	count = netdev_mc_count(netdev);
	mcast_info =
		kzalloc((sizeof(*mcast_info) + (count * NRF_WIFI_ETH_ADDR_LEN)),
			GFP_KERNEL);

	if (!mcast_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	netdev_for_each_mc_addr(ha, netdev) {
		memcpy(((char *)(mcast_info->mac_addr) +
			(indx * NRF_WIFI_ETH_ADDR_LEN)),
		       ha->addr, NRF_WIFI_ETH_ADDR_LEN);
		indx++;
	}
	status = nrf_wifi_fmac_set_mcast_addr(rpu_ctx_lnx->rpu_ctx,
					      vif_ctx_lnx->if_idx, mcast_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_chg_vif_state failed\n", __func__);
		goto out;
	}

out:
	if (mcast_info)
		kfree(mcast_info);
}

void nrf_wifi_netdev_frame_rx_callbk_fn(void *os_vif_ctx, void *frm)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct sk_buff *skb = frm;
	struct net_device *netdev = NULL;

	vif_ctx_lnx = os_vif_ctx;
	netdev = vif_ctx_lnx->netdev;

	skb->dev = netdev;
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */

	netif_rx(skb);
}

void nrf_wifi_netdev_rx_sniffer_frm(void *os_vif_ctx, void *frm,
				struct raw_rx_pkt_header *raw_rx_hdr,
				bool pkt_free)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx_def *def_dev_ctx = NULL;
	struct wireless_dev *wdev = NULL;
	struct sk_buff *skb = frm;
	struct net_device *netdev = NULL;
	unsigned char i = 0;

	if (skb == NULL) {
		pr_info("%s: skb==NULL something wrong\n", __func__);
		return;
	}

	// Find correct monitor channel
	// TODO see if this can be fixed in the library or if this is a firmware issue
	vif_ctx_lnx = os_vif_ctx;
	wdev = vif_ctx_lnx->wdev;
	if (wdev && wdev->iftype == NL80211_IFTYPE_MONITOR) {
		netdev = vif_ctx_lnx->netdev;
	} else {
		def_dev_ctx = wifi_dev_priv(vif_ctx_lnx->rpu_ctx->rpu_ctx);
		for (i = 0; i < MAX_NUM_VIFS; i++) {
			if (def_dev_ctx->vif_ctx[i] == NULL) {
				continue;
			}
			vif_ctx_lnx = 
				(struct nrf_wifi_fmac_vif_ctx_lnx
					 *)(def_dev_ctx->vif_ctx[i]->os_vif_ctx);
			wdev = vif_ctx_lnx->wdev;
			if (wdev && wdev->iftype == NL80211_IFTYPE_MONITOR) {
				netdev = vif_ctx_lnx->netdev;
				break;
			} else {
				vif_ctx_lnx = NULL;
			}
		}
	}

	if (netdev == NULL) {
		pr_err("%s: No monitor channel found\n", __func__);
		return;
	}

	skb = (struct sk_buff *)skb_raw_pkt_from_nbuf(netdev, skb, sizeof(struct raw_rx_pkt_header),
								raw_rx_hdr, pkt_free);
	if (skb == NULL) {
		pr_info("%s: unable to convert sniffer packet\n", __func__);
		goto out;
	}

	netif_rx(skb);

out:
	if (pkt_free) {
		// kfree_skb(skb);
		// pr_info("%s: free\n", __func__);
	}
}

void nrf_wifi_netdev_change_rx_flags(struct net_device *dev, int flags)
{
	pr_info("%s: change rx flags=0x%04x", __func__, flags);
}

void nrf_wifi_netdev_set_rx_mode(struct net_device *dev)
{
	struct wireless_dev *wdev;
	wdev = dev->ieee80211_ptr;

	pr_info("%s: Set rx mode, mode=%d", __func__, wdev->iftype);
}

enum nrf_wifi_status nrf_wifi_netdev_if_state_chg_callbk_fn(
	void *vif_ctx, enum nrf_wifi_fmac_if_carr_state if_state)
{
	enum nrf_wifi_status status = NRF_WIFI_STATUS_FAIL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct net_device *netdev = NULL;
	pr_info("%s: state chg carr=%d\n", __func__, if_state);
	if (!vif_ctx) {
		pr_err("%s: Invalid parameters\n", __func__);
		goto out;
	}

	vif_ctx_lnx = (struct nrf_wifi_fmac_vif_ctx_lnx *)vif_ctx;
	netdev = vif_ctx_lnx->netdev;

	if (if_state == NRF_WIFI_FMAC_IF_CARR_STATE_ON)
		netif_carrier_on(netdev);
	else if (if_state == NRF_WIFI_FMAC_IF_CARR_STATE_OFF)
		netif_carrier_off(netdev);
	else {
		pr_err("%s: Invalid interface state %d\n", __func__, if_state);
		goto out;
	}
	vif_ctx_lnx->if_carr_state = if_state;

	status = NRF_WIFI_STATUS_SUCCESS;
out:
	return status;
}

const struct net_device_ops nrf_wifi_netdev_ops = {
	.ndo_open = nrf_wifi_netdev_open,
	.ndo_stop = nrf_wifi_netdev_close,
	.ndo_set_mac_address = nrf_wifi_set_mac_address,
#ifdef CONFIG_NRF700X_DATA_TX
	.ndo_start_xmit = nrf_wifi_netdev_start_xmit,
#endif /* CONFIG_NRF700X_DATA_TX */
// #ifdef CONFIG_NRF700X_RAW_DATA_RX
// 	.ndo_change_rx_flags = nrf_wifi_netdev_change_rx_flags,
// 	.ndo_set_rx_mode = nrf_wifi_netdev_set_rx_mode,
// #endif
};

struct nrf_wifi_fmac_vif_ctx_lnx *
nrf_wifi_netdev_add_vif(struct nrf_wifi_ctx_lnx *rpu_ctx_lnx,
			const char *if_name, struct wireless_dev *wdev,
			char *mac_addr, bool hasLock)
{
	struct net_device *netdev = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx = NULL;
	int ret = 0;

	ASSERT_RTNL();

	netdev = alloc_etherdev(sizeof(struct nrf_wifi_fmac_vif_ctx_lnx));

	if (!netdev) {
		pr_err("%s: Unable to allocate memory for a new netdev\n",
		       __func__);
		goto out;
	}
#ifdef CONFIG_MEM_DEBUG
	pr_info("%s: netdev addr=%016lx\n", __func__, (long unsigned int)netdev);
#endif

	vif_ctx_lnx = netdev_priv(netdev);
	vif_ctx_lnx->rpu_ctx = rpu_ctx_lnx;
	vif_ctx_lnx->netdev = netdev;
	fmac_dev_ctx = rpu_ctx_lnx->rpu_ctx;
#ifdef CONFIG_MEM_DEBUG
	pr_info("%s: vif_ctx_lnx addr=%016lx\n", __func__, (long unsigned int)vif_ctx_lnx);
#endif

	if (wdev->iftype == NL80211_IFTYPE_MONITOR) {
		netdev->type = ARPHRD_IEEE80211_RADIOTAP; //ARPHRD_IEEE80211;
	} else {
		netdev->type = ARPHRD_ETHER;
	}
	netdev->netdev_ops = &nrf_wifi_netdev_ops;

	strncpy(netdev->name, if_name, sizeof(netdev->name) - 1);

	ether_addr_copy(netdev->dev_addr, mac_addr);

	netdev->ieee80211_ptr = wdev;

	netdev->needed_headroom = TX_BUF_HEADROOM;

	netdev->priv_destructor = free_netdev;
#ifdef CONFIG_NRF700X_DATA_TX
	vif_ctx_lnx->data_txq =
		nrf_wifi_utils_q_alloc(fmac_dev_ctx->fpriv->opriv);
	if (vif_ctx_lnx->data_txq == NULL) {
		goto err_reg_netdev;
	}
	INIT_WORK(&vif_ctx_lnx->ws_data_tx, nrf_cfg80211_data_tx_routine);
	INIT_WORK(&vif_ctx_lnx->ws_queue_monitor,
		  nrf_cfg80211_queue_monitor_routine);
#endif

	SET_NETDEV_DEV(netdev, wiphy_dev(wdev->wiphy));
	
	if (hasLock) {
		ret = register_netdevice(netdev);
	} else {
		ret = cfg80211_register_netdevice(netdev);
	}

	if (ret) {
		pr_err("%s: Unable to register netdev, ret=%d\n", __func__,
		       ret);
		goto err_reg_netdev;
	}
	wdev->netdev = netdev;

err_reg_netdev:
	if (ret) {
		free_netdev(netdev);
		netdev = NULL;
		vif_ctx_lnx = NULL;
	}
out:
	return vif_ctx_lnx;
}

void nrf_wifi_netdev_del_vif(struct net_device *netdev, bool hasLock)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx = NULL;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
	fmac_dev_ctx = rpu_ctx_lnx->rpu_ctx;

#ifdef CONFIG_MEM_DEBUG
	pr_info("%s: delete idx=%d\n"
		"netdev addr=%016lx\nvif_ctx_lnx=%016lx", __func__, 
		vif_ctx_lnx->if_idx, (long unsigned int)netdev, (long unsigned int)vif_ctx_lnx);
#endif

	nrf_wifi_utils_q_free(fmac_dev_ctx->fpriv->opriv,
			      vif_ctx_lnx->data_txq);
	
	if (hasLock) {
		unregister_netdevice(netdev);
	} else {
		cfg80211_unregister_netdevice(netdev);
	}
	netdev->ieee80211_ptr = NULL;
}

inline void nrf_wifi_netdev_chg_vif(struct net_device *netdev)
{
	struct wireless_dev* wdev;

	wdev = netdev->ieee80211_ptr;

	if (wdev->iftype == NL80211_IFTYPE_MONITOR) {
		netdev->type = ARPHRD_IEEE80211_RADIOTAP; //ARPHRD_IEEE80211;
	} else {
		netdev->type = ARPHRD_ETHER;
	}
}
#endif /* !CONFIG_NRF700X_RADIO_TEST */
