/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: GPL-2.0
 */


#include <linux/rtnetlink.h>
#include <net/cfg80211.h>

#include "host_rpu_umac_if.h"
#include "main.h"
#include "fmac_main.h"
#include "net_stack.h"
#include "fmac_api.h"
#include "fmac_util.h"

extern const struct ieee80211_txrx_stypes ieee80211_default_mgmt_stypes[];
extern struct ieee80211_supported_band band_2ghz;
extern struct ieee80211_supported_band band_5ghz;
extern const struct ieee80211_iface_combination iface_combinations[];
int get_scan_results;
unsigned long long cmd_frame_cookie_g;

#define CARR_ON_TIMEOUT_MS 5000
#define ACTION_FRAME_RESP_TIMEOUT_MS 5000

#ifndef CONFIG_NRF700X_RADIO_TEST
struct wireless_dev *nrf_wifi_cfg80211_add_vif(struct wiphy *wiphy,
					       const char *name,
					       unsigned char name_assign_type,
					       enum nl80211_iftype type,
					       struct vif_params *params)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_add_vif_info *add_vif_info = NULL;
	unsigned char mac_addr[ETH_ALEN];
	
	ASSERT_RTNL();

	rpu_ctx_lnx = wiphy_priv(wiphy);

	if (mac_addr == NULL) {
		pr_err("%s: Mac address is null\n", __func__);
		goto err;
	}
	
	vif_ctx_lnx =
		nrf_wifi_wlan_fmac_add_vif(rpu_ctx_lnx, name, mac_addr, type, false);

	if (!vif_ctx_lnx) {
		pr_err("%s: Unable to add interface to the stack\n", __func__);
		goto err;
	}

	add_vif_info = kzalloc(sizeof(*add_vif_info), GFP_KERNEL);

	if (!add_vif_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto err;
	}
#ifdef CONFIG_MEM_DEBUG
	pr_info("%s: add_vif_info=%016lx\n", __func__, (long unsigned int)add_vif_info);
#endif

	if (type == NL80211_IFTYPE_MONITOR) {
		add_vif_info->iftype = NL80211_IFTYPE_STATION;
	} else {
		add_vif_info->iftype = type;
	}

	memcpy(add_vif_info->ifacename, name, strlen(name));

	ether_addr_copy(add_vif_info->mac_addr, mac_addr);
	vif_ctx_lnx->if_idx = nrf_wifi_fmac_add_vif(rpu_ctx_lnx->rpu_ctx,
						    vif_ctx_lnx, add_vif_info);

	if (vif_ctx_lnx->if_idx >= MAX_NUM_VIFS) {
		pr_err("%s: nrf_wifi_fmac_add_vif failed\n", __func__);
		goto err;
	}

	if (vif_ctx_lnx->if_idx == 0) {
		rpu_ctx_lnx->def_vif_ctx = vif_ctx_lnx;
	}

	goto out;

err:
	if (vif_ctx_lnx) {
		nrf_wifi_wlan_fmac_del_vif(vif_ctx_lnx, false);
		vif_ctx_lnx = NULL;
	}
out:
	if (add_vif_info) {
#ifdef CONFIG_MEM_DEBUG
		pr_info("%s: Free add_vif_info=%016lx\n", __func__, (long unsigned int)add_vif_info);
#endif
		kfree(add_vif_info);
	}

	if (vif_ctx_lnx)
		return vif_ctx_lnx->wdev;
	else
		return ERR_PTR(-EOPNOTSUPP);
}

int nrf_wifi_cfg80211_del_vif(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx_def *def_dev_ctx = NULL;
	struct net_device *netdev = NULL;
	int status = -1;

	netdev = wdev->netdev;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
	fmac_dev_ctx = rpu_ctx_lnx->rpu_ctx;
	def_dev_ctx = wifi_dev_priv(fmac_dev_ctx);

	if (vif_ctx_lnx->if_idx == 0) {
		pr_err("%s: deleting default interface not supported\n",
		       __func__);
		goto out;
	}

	nrf_wifi_wlan_fmac_del_vif(vif_ctx_lnx, false);

	status = nrf_wifi_fmac_del_vif(rpu_ctx_lnx->rpu_ctx,
				       vif_ctx_lnx->if_idx);

	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_del_vif failed\n", __func__);
		goto out;
	}

	def_dev_ctx->vif_ctx[vif_ctx_lnx->if_idx] = NULL;
	netdev = NULL;
	wdev = NULL;
out:
	return status;
}

int nrf_wifi_cfg80211_chg_vif(struct wiphy *wiphy,
					struct net_device *netdev,
			      	enum nl80211_iftype iftype,
			      	struct vif_params *params)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_chg_vif_attr_info *vif_info = NULL;
	struct nrf_wifi_umac_chg_vif_state_info *vif_state_info = NULL;
	int status = -1;
	unsigned int count = 50;

	pr_info("%s: Changing to %d\n", __func__, iftype);

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	vif_info = kzalloc(sizeof(*vif_info), GFP_KERNEL);
	vif_state_info = kzalloc(sizeof(*vif_state_info), GFP_KERNEL);

	if (!vif_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (iftype == wdev->iftype) {
		pr_warn("%s: already set to interface type\n", __func__);
		goto out;
	}

	vif_info->iftype = iftype;
	vif_info->nrf_wifi_use_4addr = params->use_4addr;

	if (iftype == NL80211_IFTYPE_MONITOR || 
		(wdev->iftype == NL80211_IFTYPE_MONITOR)) {
		pr_info("%s: Skipping\n", __func__);
		status = 0;
		// If we are switching from or to monitor mode, then we don't need to change virtual interface
		goto update_if;
	} else if (iftype == NL80211_IFTYPE_AP) {
		pr_info("%s: Changing to ap\n", __func__);
		vif_info->iftype = NRF_WIFI_IFTYPE_AP;
		vif_info->nrf_wifi_use_4addr = 0;
	}

#if 0
	// First bring interface down
	vif_state_info->state = 0;
	vif_state_info->if_index = vif_ctx_lnx->if_idx;

	status = nrf_wifi_fmac_chg_vif_state(rpu_ctx_lnx->rpu_ctx,
					     vif_ctx_lnx->if_idx, vif_state_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_chg_vif_state failed\n", __func__);
		goto out;
	}

	while(vif_ctx_lnx->if_carr_state != NRF_WIFI_FMAC_IF_CARR_STATE_OFF &&
		count-- > 0) {
		msleep(200);
	}

	if (vif_ctx_lnx->if_carr_state != NRF_WIFI_FMAC_IF_CARR_STATE_OFF) {
		pr_err("%s: Unable to bring interface down\n", __func__);
	}
	count = 50;
#endif

	vif_ctx_lnx->event_set_if = 0;
	status = nrf_wifi_fmac_chg_vif(rpu_ctx_lnx->rpu_ctx,
				       	vif_ctx_lnx->if_idx, vif_info);
	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_vif failed\n", __func__);
		goto out;
	}

	pr_debug("%s: Waiting for response from RPU (change VIF)\n", __func__);

	while (!vif_ctx_lnx->event_set_if && (count-- > 0))
		msleep_interruptible(200);

	if (!vif_ctx_lnx->event_set_if) {
		status = -ETIMEDOUT;
		pr_err("%s:Timed out waiting for response from RPU (change VIF)\n",
		       __func__);
		goto out;
	}

	if (vif_ctx_lnx->status_set_if) {
		status = vif_ctx_lnx->status_set_if;
		goto out;
	}

	nrf_wifi_fmac_vif_update_if_type(rpu_ctx_lnx->rpu_ctx,
					 vif_ctx_lnx->if_idx, vif_info->iftype );

#if 0
	// Bring interface back up
	vif_state_info->state = 1;
	vif_state_info->if_index = vif_ctx_lnx->if_idx;

	status = nrf_wifi_fmac_chg_vif_state(rpu_ctx_lnx->rpu_ctx,
					     vif_ctx_lnx->if_idx, vif_state_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_chg_vif_state failed\n", __func__);
		goto out;
	}

	while(vif_ctx_lnx->if_carr_state != NRF_WIFI_FMAC_IF_CARR_STATE_ON &&
		count-- > 0) {
		msleep(200);
	}

	if (vif_ctx_lnx->if_carr_state != NRF_WIFI_FMAC_IF_CARR_STATE_ON) {
		pr_err("%s: Unable to bring interface down\n", __func__);
	}
#endif

update_if:
	wdev->iftype = iftype;
	nrf_wifi_netdev_chg_vif(netdev);

out:
	vif_ctx_lnx->event_set_if = 0;

	if (vif_info)
		kfree(vif_info);

	if (vif_state_info)
		kfree(vif_state_info);

	return status;
}

int nrf_wifi_cfg80211_add_key(struct wiphy *wiphy, struct net_device *netdev,
			      u8 key_index, bool pairwise, const u8 *mac_addr,
			      struct key_params *params)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_key_info *key_info = NULL;
	int status = -1;

	if (!params) {
		pr_err("%s: Invalid parameters (params = %p)\n", __func__,
		       params);
		goto out;
	}

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	key_info = kzalloc(sizeof(*key_info), GFP_KERNEL);

	if (!key_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (params->key_len) {
		memcpy(key_info->key.nrf_wifi_key, params->key,
		       params->key_len);
		key_info->key.nrf_wifi_key_len = params->key_len;
		key_info->key_idx = key_index;
	}

	if (params->seq_len) {
		memcpy(key_info->seq.nrf_wifi_seq, params->seq,
		       params->seq_len);
		key_info->seq.nrf_wifi_seq_len = params->seq_len;
	}

	key_info->cipher_suite = params->cipher;

	if (pairwise)
		key_info->key_type = NRF_WIFI_KEYTYPE_PAIRWISE;
	else
		key_info->key_type = NRF_WIFI_KEYTYPE_GROUP;

	status = nrf_wifi_fmac_add_key(rpu_ctx_lnx->rpu_ctx,
				       vif_ctx_lnx->if_idx, key_info, mac_addr);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_add_key failed\n", __func__);
		goto out;
	}

out:
	if (key_info)
		kfree(key_info);

	return status;
}

int nrf_wifi_cfg80211_del_key(struct wiphy *wiphy, struct net_device *netdev,
			      u8 key_idx, bool pairwise, const u8 *mac_addr)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_key_info *key_info = NULL;
	int status = -1;

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	key_info = kzalloc(sizeof(*key_info), GFP_KERNEL);

	if (!key_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	key_info->key_idx = key_idx;

	key_info->key_type = pairwise ? NL80211_KEYTYPE_PAIRWISE :
					NL80211_KEYTYPE_GROUP;

	status = nrf_wifi_fmac_del_key(rpu_ctx_lnx->rpu_ctx,
				       vif_ctx_lnx->if_idx, key_info, mac_addr);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_del_key failed\n", __func__);
		goto out;
	}

out:
	if (key_info)
		kfree(key_info);

	return status;
}

int nrf_wifi_cfg80211_set_def_key(struct wiphy *wiphy,
				  struct net_device *netdev, u8 key_index,
				  bool unicast, bool multicast)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_key_info *key_info = NULL;
	int status = -1;

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	key_info = kzalloc(sizeof(*key_info), GFP_KERNEL);

	if (!key_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (unicast)
		key_info->nrf_wifi_flags |= NRF_WIFI_KEY_DEFAULT_TYPE_UNICAST;

	if (multicast)
		key_info->nrf_wifi_flags |= NRF_WIFI_KEY_DEFAULT_TYPE_MULTICAST;

	key_info->nrf_wifi_flags |= NRF_WIFI_KEY_DEFAULT;

	key_info->key_idx = key_index;

	status = nrf_wifi_fmac_set_key(rpu_ctx_lnx->rpu_ctx,
				       vif_ctx_lnx->if_idx, key_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_key failed\n", __func__);
		goto out;
	}

out:
	if (key_info)
		kfree(key_info);

	return status;
}

int nrf_wifi_cfg80211_set_def_mgmt_key(struct wiphy *wiphy,
				       struct net_device *netdev, u8 key_index)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_key_info *key_info = NULL;
	int status = -1;

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	key_info = kzalloc(sizeof(*key_info), GFP_KERNEL);

	if (!key_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	key_info->key_idx = key_index;

	key_info->nrf_wifi_flags |= NRF_WIFI_KEY_DEFAULT_MGMT;

	status = nrf_wifi_fmac_set_key(rpu_ctx_lnx->rpu_ctx,
				       vif_ctx_lnx->if_idx, key_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_key failed\n", __func__);
		goto out;
	}

out:
	if (key_info)
		kfree(key_info);

	return status;
}

int nrf_wifi_cfg80211_start_ap(struct wiphy *wiphy, struct net_device *netdev,
			       struct cfg80211_ap_settings *params)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_start_ap_info *start_ap_info = NULL;
#if 0
	struct nrf_wifi_umac_chg_vif_state_info *vif_info = NULL;
#endif
	int status = -1;
	unsigned int count = 5000;

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	start_ap_info = kzalloc(sizeof(*start_ap_info), GFP_KERNEL);

	if (!start_ap_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	start_ap_info->beacon_interval = params->beacon_interval;
	start_ap_info->dtim_period = params->dtim_period;
	pr_info("%s: beacon int=%d", __func__, start_ap_info->beacon_interval);
	start_ap_info->auth_type = params->auth_type;

	if (params->privacy == 1)
		start_ap_info->nrf_wifi_flags =
			NRF_WIFI_CMD_BEACON_INFO_PRIVACY;
	else
		start_ap_info->nrf_wifi_flags =
			NRF_WIFI_CMD_BEACON_INFO_CONTROL_PORT_NO_ENCRYPT;

	start_ap_info->freq_params.frequency =
		params->chandef.chan->center_freq;
	start_ap_info->freq_params.channel_width = params->chandef.width;
	start_ap_info->freq_params.center_frequency1 =
		params->chandef.center_freq1;
	start_ap_info->freq_params.center_frequency2 =
		params->chandef.center_freq2;

	if (params->chandef.width == NL80211_CHAN_WIDTH_20_NOHT)
		start_ap_info->freq_params.channel_type = NRF_WIFI_CHAN_NO_HT;
	else if (params->chandef.width == NL80211_CHAN_WIDTH_20)
		start_ap_info->freq_params.channel_type = NRF_WIFI_CHAN_HT20;
	else if ((params->chandef.width == NL80211_CHAN_WIDTH_40) &&
		 (params->chandef.center_freq1 ==
		  params->chandef.chan->center_freq + 10))
		start_ap_info->freq_params.channel_type =
			NRF_WIFI_CHAN_HT40PLUS;
	else if ((params->chandef.width == NL80211_CHAN_WIDTH_40) &&
		 (params->chandef.center_freq1 ==
		  params->chandef.chan->center_freq - 10))
		start_ap_info->freq_params.channel_type =
			NRF_WIFI_CHAN_HT40MINUS;

	if (params->ssid) {
		memcpy(start_ap_info->ssid.nrf_wifi_ssid, params->ssid,
		       params->ssid_len);

		start_ap_info->ssid.nrf_wifi_ssid_len = params->ssid_len;
	}

	start_ap_info->hidden_ssid = params->hidden_ssid;
	start_ap_info->smps_mode = params->smps_mode;
	start_ap_info->inactivity_timeout = params->inactivity_timeout;

	start_ap_info->connect_common_info.wpa_versions =
		params->crypto.wpa_versions;
	start_ap_info->connect_common_info.cipher_suite_group =
		params->crypto.cipher_group;
	start_ap_info->connect_common_info.control_port_no_encrypt =
		params->crypto.control_port_no_encrypt;
	start_ap_info->connect_common_info.control_port_ether_type =
		cpu_to_be16(params->crypto.control_port_ethertype);

	if (params->crypto.n_ciphers_pairwise > 0) {
		memcpy(start_ap_info->connect_common_info.cipher_suites_pairwise,
		       params->crypto.ciphers_pairwise,
		       params->crypto.n_ciphers_pairwise * 4);
		// memset(start_ap_info->connect_common_info.cipher_suites_pairwise, 0, 
		// 		params->crypto.n_ciphers_pairwise * 4);

		start_ap_info->connect_common_info.num_cipher_suites_pairwise =
			(params->crypto.n_ciphers_pairwise * 4);
	}

	if (params->crypto.n_akm_suites > 0) {
		memcpy(start_ap_info->connect_common_info.akm_suites,
		       params->crypto.akm_suites,
		       params->crypto.n_akm_suites * 4);

		start_ap_info->connect_common_info.num_akm_suites =
			(params->crypto.n_akm_suites * 4);
	}

	start_ap_info->connect_common_info.control_port =
		params->crypto.control_port;

	start_ap_info->connect_common_info.control_port_no_encrypt = true;

	if (params->beacon.head_len > 0) {
		memcpy(start_ap_info->beacon_data.head, params->beacon.head,
		       params->beacon.head_len);

		start_ap_info->beacon_data.head_len = params->beacon.head_len;
	}

	if (params->beacon.tail_len > 0) {
		memcpy(start_ap_info->beacon_data.tail, params->beacon.tail,
		       params->beacon.tail_len);

		start_ap_info->beacon_data.tail_len = params->beacon.tail_len;
	}

	if (params->beacon.probe_resp_len > 0) {
		memcpy(start_ap_info->beacon_data.probe_resp,
		       params->beacon.probe_resp,
		       params->beacon.probe_resp_len);

		start_ap_info->beacon_data.probe_resp_len =
			params->beacon.probe_resp_len;
	}
#if 0
	if ((params->p2p_ctwindow > 0) && (params->p2p_ctwindow < 127)) {
		start_ap_info->p2p_go_ctwindow = params->p2p_ctwindow;
		start_ap_info->p2p_opp_ps = params->p2p_opp_ps;
	}
#endif

	pr_info("%s: Starting\n", __func__);
	vif_ctx_lnx->if_carr_state = NRF_WIFI_FMAC_IF_CARR_STATE_OFF;
	status = nrf_wifi_fmac_start_ap(rpu_ctx_lnx->rpu_ctx, 
									vif_ctx_lnx->if_idx,
									start_ap_info);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_start_ap failed", __func__);
		goto out;
	}

	while(vif_ctx_lnx->if_carr_state != NRF_WIFI_FMAC_IF_CARR_STATE_ON &&
			count-- > 0) { msleep_interruptible(1); }

	if (vif_ctx_lnx->if_carr_state != NRF_WIFI_FMAC_IF_CARR_STATE_ON) {
		pr_err("%s: Carrier on event not received in 5000ms", __func__);
	}
#if 0
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
#endif
out:
	if (start_ap_info)
		kfree(start_ap_info);

#if 0
	if (vif_info)
		kfree(vif_info);
#endif

	return status;
}

int nrf_wifi_cfg80211_chg_bcn(struct wiphy *wiphy, struct net_device *netdev,
			      struct cfg80211_beacon_data *params)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_set_beacon_info *bcn_info = NULL;
	int status = -1;
	pr_info("%s: Changing\n", __func__);
	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	bcn_info = kzalloc(sizeof(*bcn_info), GFP_KERNEL);

	if (!bcn_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (params->head_len > 0) {
		memcpy(bcn_info->beacon_data.head, params->head,
		       params->head_len);

		bcn_info->beacon_data.head_len = params->head_len;
	}

	if (params->tail_len > 0) {
		memcpy(bcn_info->beacon_data.tail, params->tail,
		       params->tail_len);

		bcn_info->beacon_data.tail_len = params->tail_len;
	}

	if (params->probe_resp_len > 0) {
		memcpy(bcn_info->beacon_data.probe_resp, params->probe_resp,
		       params->probe_resp_len);

		bcn_info->beacon_data.probe_resp_len = params->probe_resp_len;
	}

	status = nrf_wifi_fmac_chg_bcn(rpu_ctx_lnx->rpu_ctx,
									vif_ctx_lnx->if_idx,
									bcn_info);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_chg_bcn failed\n", __func__);
		goto out;
	}
out:
	if (bcn_info)
		kfree(bcn_info);

	return status;
}

int nrf_wifi_cfg80211_stop_ap(struct wiphy *wiphy, struct net_device *netdev)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	int status = -1;

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	status = nrf_wifi_fmac_stop_ap(rpu_ctx_lnx->rpu_ctx,
									vif_ctx_lnx->if_idx);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_stop_ap failed\n", __func__);
	}

	return status;
}

int nrf_wifi_cfg80211_connect(struct wiphy *wiphy, struct net_device *netdev,
							struct cfg80211_connect_params *params)
{
	pr_info("%s: connecting\n", __func__);
	return 0;
}

int nrf_wifi_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *netdev, u16 reason_code)
{
	pr_info("%s: Disconnect reason=%d", __func__, reason_code);
	return 0;
}

int nrf_wifi_cfg80211_add_sta(struct wiphy *wiphy, struct net_device *netdev,
			      const u8 *mac, struct station_parameters *params)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_add_sta_info *add_sta_info = NULL;
	// struct nl80211_sta_flag_update *flags2 = NULL;
	int status = -1;
	pr_info("%s: adding\n", __func__);
	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
	pr_info("%s: alloc\n", __func__);
	add_sta_info = kzalloc(sizeof(*add_sta_info), GFP_KERNEL);

	if (!add_sta_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	add_sta_info->aid = params->aid;

	if (params->sta_modify_mask & STATION_PARAM_APPLY_CAPABILITY)
		add_sta_info->sta_capability = params->capability;

	add_sta_info->nrf_wifi_listen_interval = params->listen_interval;
pr_info("%s: support rates\n", __func__);
	if (params->supported_rates_len > 0) {
		memcpy(add_sta_info->supp_rates.rates, params->supported_rates,
		       params->supported_rates_len);

		add_sta_info->supp_rates.nrf_wifi_num_rates =
			params->supported_rates_len;
	}
pr_info("%s: ext capability\n", __func__);
	if (params->ext_capab_len > 0) {
		memcpy(add_sta_info->ext_capability.ext_capability,
		       params->ext_capab, params->ext_capab_len);

		add_sta_info->ext_capability.ext_capability_len =
			params->ext_capab_len;
	}
pr_info("%s: supported channels\n", __func__);
	if (params->supported_channels_len > 0) {
		memcpy(add_sta_info->supported_channels.supported_channels,
		       params->supported_channels,
		       params->supported_channels_len);

		add_sta_info->supported_channels.supported_channels_len =
			params->supported_channels_len;
	}
pr_info("%s: support oper classes\n", __func__);
	if (params->supported_oper_classes_len > 0) {
		memcpy(add_sta_info->supported_oper_classes.supported_oper_classes,
		       params->supported_oper_classes,
		       params->supported_oper_classes_len);

		add_sta_info->supported_oper_classes.supported_oper_classes_len =
			params->supported_oper_classes_len;
	}
	// flags2->mask = params->sta_flags_mask;
	// flags2->set = params->sta_flags_set;
pr_info("%s: ht_capa\n", __func__);
	if (params->ht_capa)
		memcpy(add_sta_info->ht_capability, params->ht_capa,
		       sizeof(struct ieee80211_ht_cap));
pr_info("%s: vht_capa\n", __func__);
	if (params->vht_capa)
		memcpy(add_sta_info->vht_capability, params->vht_capa,
		       sizeof(struct ieee80211_vht_cap));

	pr_info("%s: ethercopy\n", __func__);
	ether_addr_copy(add_sta_info->mac_addr, mac);

	if (params->opmode_notif_used)
		add_sta_info->opmode_notif =
			(unsigned char)params->opmode_notif;

	if (params->uapsd_queues)
		add_sta_info->wme_uapsd_queues = params->uapsd_queues;

	if (params->max_sp)
		add_sta_info->wme_max_sp = params->max_sp;
	pr_info("%s: station\n", __func__);
	status = nrf_wifi_fmac_add_sta(rpu_ctx_lnx->rpu_ctx, vif_ctx_lnx->if_idx, add_sta_info);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_add_sta failed\n", __func__);
		goto out;
	}
out:
	if (add_sta_info)
		kfree(add_sta_info);

	return status;
}

int nrf_wifi_cfg80211_del_sta(struct wiphy *wiphy, struct net_device *netdev,
			      struct station_del_parameters *params)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_del_sta_info *del_sta_info = NULL;
	int status = -1;

	pr_info("%s: deleting\n", __func__);

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	del_sta_info = kzalloc(sizeof(*del_sta_info), GFP_KERNEL);

	if (!del_sta_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (params->mac)
		ether_addr_copy(del_sta_info->mac_addr, params->mac);

	if (params->subtype)
		del_sta_info->mgmt_subtype = params->subtype;

	if (params->reason_code)
		del_sta_info->reason_code = params->reason_code;

	status = nrf_wifi_fmac_del_sta(rpu_ctx_lnx->rpu_ctx, vif_ctx_lnx->if_idx, del_sta_info);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_del_sta failed\n", __func__);
		goto out;
	}

out:
	if (del_sta_info)
		kfree(del_sta_info);

	return status;
}

int nrf_wifi_cfg80211_chg_sta(struct wiphy *wiphy, struct net_device *netdev,
			      const u8 *mac, struct station_parameters *params)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_chg_sta_info *chg_sta_info = NULL;
	struct nrf_wifi_sta_flag_update *flags2_info = NULL;
	struct nl80211_sta_flag_update *flags2 = NULL;
	int status = -1;

	pr_info("%s: Changing\n", __func__);

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	chg_sta_info = kzalloc(sizeof(*chg_sta_info), GFP_KERNEL);

	if (!chg_sta_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (params->aid)
		chg_sta_info->aid = params->aid;

	chg_sta_info->nrf_wifi_listen_interval = params->listen_interval;

	if (params->supported_channels_len > 0) {
		memcpy(chg_sta_info->supported_channels.supported_channels,
		       params->supported_channels,
		       params->supported_channels_len);

		chg_sta_info->supported_channels.supported_channels_len =
			params->supported_channels_len;
	}

	if (params->supported_oper_classes_len > 0) {
		memcpy(chg_sta_info->supported_oper_classes
			       .supported_oper_classes,
		       params->supported_oper_classes,
		       params->supported_oper_classes_len);

		chg_sta_info->supported_oper_classes.supported_oper_classes_len =
			params->supported_oper_classes_len;
	}

	flags2_info = &chg_sta_info->sta_flags2;
	flags2 = (struct nl80211_sta_flag_update *)flags2_info;

	flags2->mask = params->sta_flags_mask;
	flags2->set = params->sta_flags_set;

	ether_addr_copy(chg_sta_info->mac_addr, mac);

	if (params->opmode_notif_used)
		chg_sta_info->opmode_notif =
			(unsigned char)params->opmode_notif;

	if (params->max_sp)
		chg_sta_info->wme_max_sp = params->max_sp;

	status = nrf_wifi_fmac_chg_sta(rpu_ctx_lnx->rpu_ctx,
				       vif_ctx_lnx->if_idx, chg_sta_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_chg_sta failed\n", __func__);
		goto out;
	}

out:
	if (chg_sta_info)
		kfree(chg_sta_info);

	return status;
}

int nrf_wifi_cfg80211_chg_bss(struct wiphy *wiphy, struct net_device *netdev,
			      struct bss_parameters *params)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_bss_info *bss_info = NULL;
	int status = -1;

	pr_info("%s: changing\n", __func__);

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	bss_info = kzalloc(sizeof(*bss_info), GFP_KERNEL);

	if (!bss_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	bss_info->ht_opmode = params->ht_opmode;
	bss_info->nrf_wifi_cts = params->use_cts_prot;
	bss_info->preamble = params->use_short_preamble;
	bss_info->nrf_wifi_slot = params->use_short_slot_time;
	bss_info->ap_isolate = params->ap_isolate;
	bss_info->num_basic_rates = params->basic_rates_len;

	memcpy(bss_info->basic_rates, params->basic_rates,
	       bss_info->num_basic_rates);

	if ((params->p2p_ctwindow > 0) && (params->p2p_ctwindow < 127)) {
		bss_info->p2p_go_ctwindow = params->p2p_ctwindow;
		bss_info->p2p_opp_ps = params->p2p_opp_ps;
	}

	status = nrf_wifi_fmac_set_bss(rpu_ctx_lnx->rpu_ctx, vif_ctx_lnx->if_idx, bss_info);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_set_bss failed\n", __func__);
		goto out;
	}

out:
	if (bss_info)
		kfree(bss_info);

	return status;
}

int nrf_wifi_cfg80211_set_txq_params(struct wiphy *wiphy,
				     struct net_device *netdev,
				     struct ieee80211_txq_params *params)
{
	pr_err("\n\n%s: Done in SET_BSS\n\n\n", __func__);

	return 0;
}

int	nrf_wifi_cfg80211_set_monitor_channel(struct wiphy *wiphy,
				       struct cfg80211_chan_def *chandef)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx_def *def_dev_ctx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct wireless_dev *wdev = NULL;
	unsigned int channel = 0;
	unsigned char i = 0;

	rpu_ctx_lnx = wiphy_priv(wiphy);
	def_dev_ctx = wifi_dev_priv(rpu_ctx_lnx->rpu_ctx);

	// Find virtual interface in monitor mode
	for (i = 0; i < MAX_NUM_VIFS; i++) {
		if (def_dev_ctx->vif_ctx[i]) {
			vif_ctx_lnx = 
				(struct nrf_wifi_fmac_vif_ctx_lnx
					 *)(def_dev_ctx->vif_ctx[i]->os_vif_ctx);
			wdev = vif_ctx_lnx->wdev;
			if (wdev && wdev->iftype == NL80211_IFTYPE_MONITOR) {
				break;
			} else {
				vif_ctx_lnx = NULL;
			}
		}
	}

	if (vif_ctx_lnx == NULL) {
		pr_err("%s: No monitor channel found\n", __func__);
		return 1;
	}

	channel = chandef->chan->hw_value;
	if (nrf_wifi_fmac_set_channel(rpu_ctx_lnx->rpu_ctx, vif_ctx_lnx->if_idx, channel) != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: Not able to set channel %d", __func__, channel);
		return -EINVAL;
	}

	def_dev_ctx->vif_ctx[vif_ctx_lnx->if_idx]->channel = channel;
	
	return 0;
}

int nrf_wifi_cfg80211_scan(struct wiphy *wiphy,
			   struct cfg80211_scan_request *req)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_scan_info *scan_info = NULL;
	int status = -1, i;
	wdev = req->wdev;
#if 1
	if (wdev->iftype == NL80211_IFTYPE_AP)
		return -EOPNOTSUPP;
#endif
	if (req->n_channels > NRF_WIFI_SCAN_MAX_NUM_FREQUENCIES)
		return -EINVAL;

	rpu_ctx_lnx = wiphy_priv(wiphy);
	vif_ctx_lnx = netdev_priv(wdev->netdev);

	req->n_channels = 0;
	scan_info =
		kzalloc((sizeof(*scan_info) +
			 (sizeof(struct nrf_wifi_channel) * req->n_channels)),
			GFP_KERNEL);

	if (!scan_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (!req->n_ssids)
		scan_info->scan_params.passive_scan = 1;

	for (i = 0; i < req->n_ssids; i++) {
		if (req->ssids[i].ssid_len == 0)
			continue;

		if (req->ssids[i].ssid_len > NRF_WIFI_MAX_SSID_LEN) {
			pr_err("%s: SSID length is too long %d\n", __func__,
			       req->ssids[i].ssid_len);
			goto out;
		}

		if (scan_info->scan_params.num_scan_ssids ==
		    NRF_WIFI_SCAN_MAX_NUM_SSIDS) {
			pr_err("%s: Max number of SSIDs reached\n", __func__);
			goto out;
		}

		memcpy(scan_info->scan_params.scan_ssids[i].nrf_wifi_ssid,
		       req->ssids[i].ssid, req->ssids[i].ssid_len);

		scan_info->scan_params.scan_ssids[i].nrf_wifi_ssid_len =
			req->ssids[i].ssid_len;

		scan_info->scan_params.num_scan_ssids++;
	}

	scan_info->scan_reason = SCAN_DISPLAY;
	status = nrf_wifi_fmac_scan(rpu_ctx_lnx->rpu_ctx, vif_ctx_lnx->if_idx,
				    scan_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_scan failed\n", __func__);
		goto out;
	}

	vif_ctx_lnx->nrf_wifi_scan_req = req;

	get_scan_results = 0;

out:
	if (scan_info)
		kfree(scan_info);
	return status;
}

void nrf_wifi_cfg80211_scan_start_callbk_fn(
	void *os_vif_ctx,
	struct nrf_wifi_umac_event_trigger_scan *scan_start_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;

	vif_ctx_lnx = os_vif_ctx;

	/* No processing needed right now */
	return;
}

static void nrf_wifi_cfg80211_scan_results(
	struct net_device *dev,
	struct nrf_wifi_umac_event_new_scan_results *new_scan_results)
{
	struct wireless_dev *wdev = NULL;
	struct wiphy *wiphy = NULL;
	struct ieee80211_channel *rx_channel = NULL;
	enum cfg80211_bss_frame_type ftype = CFG80211_BSS_FTYPE_BEACON;
	char *ie = NULL;
	int signal = 0;
	int ielen = 0;
	struct cfg80211_bss *res = NULL;

	wdev = dev->ieee80211_ptr;
	wiphy = wdev->wiphy;

	if (new_scan_results->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_MBM)
		signal = new_scan_results->signal.signal.mbm_signal;

	if (new_scan_results->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_UNSPEC)
		signal = new_scan_results->signal.signal.unspec_signal;

	rx_channel = ieee80211_get_channel(wiphy, new_scan_results->frequency);

	res = cfg80211_inform_bss_width(
		wiphy, rx_channel, NL80211_BSS_CHAN_WIDTH_20, ftype,
		new_scan_results->mac_addr, new_scan_results->ies_tsf,
		new_scan_results->capability, new_scan_results->beacon_interval,
		ie, ielen, signal, GFP_KERNEL);

	/* cfg80211_put_bss(res) ?? */
}

static void
nrf_wifi_cfg80211_scan_done(struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx,
			    int aborted)
{
	if (vif_ctx_lnx->nrf_wifi_scan_req) {
		struct cfg80211_scan_info info = {};

		info.aborted = aborted;
		cfg80211_scan_done(vif_ctx_lnx->nrf_wifi_scan_req, &info);
		vif_ctx_lnx->nrf_wifi_scan_req = NULL;
	}
}

void nrf_wifi_cfg80211_rx_bcn_prb_rsp_callbk_fn(void *os_vif_ctx, void *frm,
						unsigned short frequency,
						short signal)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct sk_buff *skb = NULL;
	struct ieee80211_mgmt *mgmt = NULL;
	struct cfg80211_inform_bss bss_meta = {};
	unsigned int len = 0;
	struct cfg80211_bss *bss = NULL;
	vif_ctx_lnx = os_vif_ctx;
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
	skb = frm;
	mgmt = (struct ieee80211_mgmt *)skb->data;
	len = skb->len;
	if (skb->len < 24 || (!ieee80211_is_probe_resp(mgmt->frame_control) &&
			      !ieee80211_is_beacon(mgmt->frame_control))) {
		return;
	}
	bss_meta.scan_width = NL80211_BSS_CHAN_WIDTH_20;
	bss_meta.signal = signal;
	bss_meta.chan = ieee80211_get_channel(rpu_ctx_lnx->wiphy, frequency);
	bss = cfg80211_inform_bss_frame_data(rpu_ctx_lnx->wiphy, &bss_meta,
					     mgmt, len, GFP_ATOMIC);
}

void nrf_wifi_cfg80211_scan_res_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_umac_event_new_scan_results *scan_res,
	unsigned int event_len, bool more_res)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;

	vif_ctx_lnx = os_vif_ctx;
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	nrf_wifi_cfg80211_scan_results(vif_ctx_lnx->netdev, scan_res);

	if (!more_res)
		nrf_wifi_cfg80211_scan_done(vif_ctx_lnx, false);
}

void umac_event_scan_done(struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_umac_cmd_get_scan_results *scan_results = NULL;
	int len = 0;

	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	len = sizeof(struct nrf_wifi_umac_cmd_get_scan_results);

	scan_results = kzalloc(len, GFP_KERNEL);

	scan_results->umac_hdr.cmd_evnt = NRF_WIFI_UMAC_CMD_GET_SCAN_RESULTS;
	scan_results->umac_hdr.ids.wdev_id = vif_ctx_lnx->if_idx;
	scan_results->umac_hdr.ids.valid_fields |=
		NRF_WIFI_INDEX_IDS_WDEV_ID_VALID;
	umac_cmd_cfg(rpu_ctx_lnx->rpu_ctx, scan_results, len);

	get_scan_results = 1;
}

void nrf_wifi_cfg80211_scan_done_callbk_fn(
	void *os_vif_ctx,
	struct nrf_wifi_umac_event_trigger_scan *scan_done_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;

	vif_ctx_lnx = os_vif_ctx;

	nrf_wifi_cfg80211_scan_done(vif_ctx_lnx, false);
}

void nrf_wifi_cfg80211_scan_abort_callbk_fn(
	void *os_vif_ctx,
	struct nrf_wifi_umac_event_trigger_scan *scan_done_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;

	vif_ctx_lnx = os_vif_ctx;

	nrf_wifi_cfg80211_scan_done(vif_ctx_lnx, true);
}

int nrf_wifi_cfg80211_auth(struct wiphy *wiphy, struct net_device *netdev,
			   struct cfg80211_auth_request *req)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_auth_info *auth_info = NULL;
	const u8 *ssid_ie = NULL;
	int status = -1;

	pr_info("%s: auth\n", __func__);

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	auth_info = kzalloc(sizeof(*auth_info), GFP_KERNEL);

	if (!auth_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	auth_info->frequency = req->bss->channel->center_freq;
	auth_info->auth_type = req->auth_type;

	memcpy(auth_info->nrf_wifi_bssid, req->bss->bssid, ETH_ALEN);

	memcpy(auth_info->bss_ie.ie, req->bss->ies->data, req->bss->ies->len);

	auth_info->bss_ie.ie_len = req->bss->ies->len;
	auth_info->scan_width = req->bss->scan_width;
	auth_info->nrf_wifi_signal = req->bss->signal;
	auth_info->capability = req->bss->capability;
	auth_info->beacon_interval = req->bss->beacon_interval;
	auth_info->tsf = req->bss->ies->tsf;
	auth_info->from_beacon = req->bss->ies->from_beacon;

	ssid_ie = cfg80211_find_ie(WLAN_EID_SSID, req->bss->ies->data,
				   req->bss->ies->len);

	auth_info->ssid.nrf_wifi_ssid_len = ssid_ie[1];

	if (auth_info->ssid.nrf_wifi_ssid_len > NRF_WIFI_MAX_SSID_LEN) {
		pr_err("%s: SSID len (%d) exceeds max length (%d)\n", __func__,
		       auth_info->ssid.nrf_wifi_ssid_len,
		       NRF_WIFI_MAX_SSID_LEN);

		status = -1;
		goto out;
	}

	memcpy(auth_info->ssid.nrf_wifi_ssid, ssid_ie + 2, ssid_ie[1]);

	if (req->key_len) {
		auth_info->key_info.key_idx = req->key_idx;

		memcpy(auth_info->key_info.key.nrf_wifi_key, req->key,
		       req->key_len);

		auth_info->key_info.key.nrf_wifi_key_len = req->key_len;

		if (req->key_len == 5)
			auth_info->key_info.cipher_suite =
				WLAN_CIPHER_SUITE_WEP40;
		else
			auth_info->key_info.cipher_suite =
				WLAN_CIPHER_SUITE_WEP104;
	}

	if (req->auth_data_len) {
		auth_info->sae.sae_data_len = req->auth_data_len;
		memcpy(auth_info->sae.sae_data, req->auth_data,
		       req->auth_data_len);
#ifdef DEBUG_MODE_SUPPORT
		pr_err("%s: SAE_DATA_LEN =  %d\n", __func__,
		       (unsigned int)req->auth_data_len);
		pr_err("%s: SAE DATA DUMP:\n", __func__);
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE, 16, 1,
			       req->auth_data, (unsigned int)req->auth_data_len,
			       1);

		pr_err("\n%s: SAE DATA DUMP send to UMAC:\n", __func__);
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE, 16, 1,
			       auth_info->sae.sae_data,
			       auth_info->sae.sae_data_len, 1);
#endif
	}
	status = nrf_wifi_fmac_auth(rpu_ctx_lnx->rpu_ctx, vif_ctx_lnx->if_idx,
				    auth_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_auth failed\n", __func__);
		goto out;
	}

out:
	if (auth_info)
		kfree(auth_info);

	return status;
}

void nrf_wifi_cfg80211_auth_resp_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_umac_event_mlme *auth_resp_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	pr_info("%s: auth resp\n", __func__);
	vif_ctx_lnx = os_vif_ctx;

	cfg80211_rx_mlme_mgmt(vif_ctx_lnx->netdev, auth_resp_event->frame.frame,
			      auth_resp_event->frame.frame_len);
}

int nrf_wifi_cfg80211_assoc(struct wiphy *wiphy, struct net_device *netdev,
			    struct cfg80211_assoc_request *req)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_umac_assoc_info *assoc_info = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	const u8 *ssid_ie = NULL;
	int status = -1;
	pr_info("%s: assoc\n", __func__);
	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	vif_ctx_lnx->bss = req->bss;

	assoc_info = kzalloc(sizeof(*assoc_info), GFP_KERNEL);

	if (!assoc_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	assoc_info->center_frequency = req->bss->channel->center_freq;

	memcpy(assoc_info->nrf_wifi_bssid, req->bss->bssid, ETH_ALEN);

	ssid_ie = cfg80211_find_ie(WLAN_EID_SSID, req->bss->ies->data,
				   req->bss->ies->len);

	assoc_info->ssid.nrf_wifi_ssid_len = ssid_ie[1];

	if (assoc_info->ssid.nrf_wifi_ssid_len > NRF_WIFI_MAX_SSID_LEN) {
		pr_err("%s: SSID len (%d) exceeds max length (%d)\n", __func__,
		       assoc_info->ssid.nrf_wifi_ssid_len,
		       NRF_WIFI_MAX_SSID_LEN);

		status = -1;
		goto out;
	}

	memcpy(assoc_info->ssid.nrf_wifi_ssid, ssid_ie + 2, ssid_ie[1]);

	/* WPA-IE */
	assoc_info->wpa_ie.ie_len = req->ie_len;

	if (req->ie_len > 0) {
		memcpy(assoc_info->wpa_ie.ie, req->ie, req->ie_len);
	}
	assoc_info->use_mfp = req->use_mfp;

	assoc_info->control_port = req->crypto.control_port;

	status = nrf_wifi_fmac_assoc(rpu_ctx_lnx->rpu_ctx, vif_ctx_lnx->if_idx,
				     assoc_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_assoc failed\n", __func__);
		goto out;
	}

out:
	if (assoc_info)
		kfree(assoc_info);

	return status;
}

void nrf_wifi_cfg80211_assoc_resp_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_umac_event_mlme *assoc_resp_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	pr_info("%s: assoc resp\n", __func__);
	vif_ctx_lnx = os_vif_ctx;

	cfg80211_rx_assoc_resp(vif_ctx_lnx->netdev, vif_ctx_lnx->bss,
			       assoc_resp_event->frame.frame,
			       assoc_resp_event->frame.frame_len, -1, NULL, 0);
}

int nrf_wifi_cfg80211_deauth(struct wiphy *wiphy, struct net_device *netdev,
			     struct cfg80211_deauth_request *req)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_disconn_info *deauth_info = NULL;
	int status = -1;

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	deauth_info = kzalloc(sizeof(*deauth_info), GFP_KERNEL);

	if (!deauth_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	deauth_info->reason_code = req->reason_code;

	memcpy(deauth_info->mac_addr, req->bssid, ETH_ALEN);

	if (req->local_state_change)
		deauth_info->nrf_wifi_flags |=
			NRF_WIFI_CMD_MLME_LOCAL_STATE_CHANGE;

	status = nrf_wifi_fmac_deauth(rpu_ctx_lnx->rpu_ctx, vif_ctx_lnx->if_idx,
				      deauth_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_deauth failed\n", __func__);
		goto out;
	}

	cfg80211_disconnected(netdev, req->reason_code, NULL, 0, true,
			      GFP_KERNEL);

out:
	return status;
}

void nrf_wifi_cfg80211_deauth_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_umac_event_mlme *deauth_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;

	vif_ctx_lnx = os_vif_ctx;

	cfg80211_tx_mlme_mgmt(vif_ctx_lnx->netdev, deauth_event->frame.frame,
			      deauth_event->frame.frame_len, false);
}

int nrf_wifi_cfg80211_disassoc(struct wiphy *wiphy, struct net_device *netdev,
			       struct cfg80211_disassoc_request *req)
{
	struct wireless_dev *wdev = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_disconn_info *disassoc_info = NULL;
	int status = -1;

	wdev = netdev->ieee80211_ptr;

	vif_ctx_lnx = netdev_priv(netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	disassoc_info = kzalloc(sizeof(*disassoc_info), GFP_KERNEL);

	if (!disassoc_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	disassoc_info->reason_code = req->reason_code;

	memcpy(disassoc_info->mac_addr, req->bss->bssid, ETH_ALEN);

	if (req->local_state_change)
		disassoc_info->nrf_wifi_flags |=
			NRF_WIFI_CMD_MLME_LOCAL_STATE_CHANGE;

	status = nrf_wifi_fmac_disassoc(rpu_ctx_lnx->rpu_ctx,
					vif_ctx_lnx->if_idx, disassoc_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_disassoc failed\n", __func__);
		goto out;
	}

	vif_ctx_lnx->bss = NULL;

	/* TODO: This is carried over from deauthentication handler.
	 * See what needs to be called here */
	cfg80211_disconnected(netdev, req->reason_code, NULL, 0, true,
			      GFP_KERNEL);
out:
	return status;
}

void nrf_wifi_cfg80211_disassoc_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_umac_event_mlme *disassoc_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;

	vif_ctx_lnx = os_vif_ctx;

	cfg80211_tx_mlme_mgmt(vif_ctx_lnx->netdev, disassoc_event->frame.frame,
			      disassoc_event->frame.frame_len, false);
}

int nrf_wifi_cfg80211_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
			      struct cfg80211_mgmt_tx_params *params,
			      u64 *cookie)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_mgmt_tx_info *mgmt_tx_info = NULL;
	int status = -1;
	unsigned int timeout = 0;
	pr_info("%s: mgmt tx\n", __func__);

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	mgmt_tx_info = kzalloc(sizeof(*mgmt_tx_info), GFP_KERNEL);

	if (!mgmt_tx_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	/* TODO */
	if (params->offchan)
		mgmt_tx_info->nrf_wifi_flags |=
			NRF_WIFI_CMD_FRAME_OFFCHANNEL_TX_OK;

	if (params->dont_wait_for_ack)
		mgmt_tx_info->nrf_wifi_flags |=
			NRF_WIFI_CMD_FRAME_DONT_WAIT_FOR_ACK;

	if (params->no_cck)
		mgmt_tx_info->nrf_wifi_flags |=
			NRF_WIFI_CMD_FRAME_TX_NO_CCK_RATE;

	if (params->chan)
		mgmt_tx_info->frequency = params->chan->center_freq;

	if (params->wait)
		mgmt_tx_info->dur = params->wait;

	if (params->len) {
		memcpy(mgmt_tx_info->frame.frame, params->buf, params->len);
		mgmt_tx_info->frame.frame_len = params->len;
	}

	mgmt_tx_info->freq_params.frequency = 2412;
	mgmt_tx_info->freq_params.channel_width = NL80211_CHAN_WIDTH_20;
	mgmt_tx_info->freq_params.center_frequency1 =
		2412; /* same as freq above */
	mgmt_tx_info->freq_params.center_frequency2 = 0;
	mgmt_tx_info->freq_params.channel_type = NL80211_CHAN_HT20;

	cmd_frame_cookie_g++;

	if (cmd_frame_cookie_g == 0)
		cmd_frame_cookie_g++;

	/* Going to RPU */
	mgmt_tx_info->host_cookie = cmd_frame_cookie_g;
	vif_ctx_lnx->cookie_resp = 0;

	/* Going to wpa_supplicant */
	*cookie = cmd_frame_cookie_g;
	pr_info("%s: Sending frame to RPU: cookie=%lld wait_time=%d no_ack=%d flags=%x params=%d", __func__,
			mgmt_tx_info->host_cookie,
			mgmt_tx_info->dur,
			mgmt_tx_info->nrf_wifi_flags & NRF_WIFI_CMD_FRAME_DONT_WAIT_FOR_ACK ? 1 : 0,
			mgmt_tx_info->nrf_wifi_flags,
			params->dont_wait_for_ack);

	status = nrf_wifi_fmac_mgmt_tx(rpu_ctx_lnx->rpu_ctx,
				       vif_ctx_lnx->if_idx, mgmt_tx_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_mgmt_tx failed\n", __func__);
		goto out;
	}

	if (params->wait || !params->dont_wait_for_ack) {
		if (!params->dont_wait_for_ack && !params->wait) {
			params->wait = ACTION_FRAME_RESP_TIMEOUT_MS;
		}

		while(!vif_ctx_lnx->cookie_resp &&
			timeout++ < params->wait) {
			msleep_interruptible(1);		
		}

		if (!vif_ctx_lnx->cookie_resp) {
			pr_err("%s: cookie response not received (%dms)", __func__, params->wait);
			status = NRF_WIFI_STATUS_FAIL;
			goto out;
		}

		cfg80211_mgmt_tx_status(vif_ctx_lnx->netdev->ieee80211_ptr, 
			mgmt_tx_info->host_cookie,
			mgmt_tx_info->frame.frame,
			mgmt_tx_info->frame.frame_len, 0,
			GFP_KERNEL);

		pr_info("%s: Finished\n", __func__);
		status = NRF_WIFI_STATUS_SUCCESS;
		goto out;
	}

out:
	if (mgmt_tx_info)
		kfree(mgmt_tx_info);

	return status;
}

void nrf_wifi_cfg80211_mgmt_frame_reg(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      struct mgmt_frame_regs *upd)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_mgmt_frame_info *frame_info = NULL;
	struct nrf_wifi_cfg80211_mgmt_registration *reg = NULL;
	bool frame_type_match = false;
	// u16 mgmt_type;
	// u16 frame_type = BIT(upd->global_stypes << 4);
	static u16 last_upd = 0;
	int status = -1;

	pr_info("%s: Updating frame reg=%04x global=%04x\n", __func__, upd->interface_stypes, upd->global_stypes);

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	frame_info = kzalloc(sizeof(*frame_info), GFP_KERNEL);

	if (!frame_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (last_upd == upd->interface_stypes) {
		pr_err("%s: no update\n", __func__);
		goto out;
	}
#if 1
	list_for_each_entry(reg, &wdev->mgmt_registrations, list) {
		pr_info("%s: reg type=%04x", __func__, le16_to_cpu(reg->frame_type));
		// if (!((le16_to_cpu(upd->interface_stypes << 4)) & le16_to_cpu(reg->frame_type)))
		if ((last_upd ^ upd->interface_stypes) != BIT(le16_to_cpu(reg->frame_type) >> 4))
			continue;
		frame_type_match = true;

		break;
	}

	if (!frame_type_match ) {
		pr_err("%s: frametype not match %04x", __func__, le16_to_cpu(reg->frame_type));
		goto out;
	}
	frame_info->frame_type = le16_to_cpu(reg->frame_type);
	pr_info("%s: frametype=%04x len=%d", __func__, frame_info->frame_type, reg->match_len);
	frame_info->frame_match.frame_match_len = reg->match_len;
	if (reg->match_len >= NRF_WIFI_FRAME_MATCH_MAX_LEN) {
		pr_err("%s: match_len too big: %d (max %d)", __func__, reg->match_len, NRF_WIFI_FRAME_MATCH_MAX_LEN);
		goto out;
	}
	memcpy(frame_info->frame_match.frame_match, reg->match, reg->match_len);

#else
	frame_info->frame_type = frame_type;
	pr_info("%s: sent=%04x frame_type=%04x global=%04x", __func__, 
		frame_info->frame_type,
		frame_type,
		upd->global_stypes);
#endif
	status = nrf_wifi_fmac_mgmt_frame_reg(rpu_ctx_lnx->rpu_ctx,
										vif_ctx_lnx->if_idx,
										frame_info);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		pr_err("%s: nrf_wifi_fmac_mgmt_frame_reg failed", __func__);
		goto out;
	}

out:
	if (frame_info)
		kfree(frame_info);
	last_upd = upd->interface_stypes;

	return;
}

void nrf_wifi_cfg80211_mgmt_rx_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_umac_event_mlme *mgmt_rx_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	bool status = false;

	vif_ctx_lnx = os_vif_ctx;
	pr_info("%s: mgmt rx callback\n", __func__);

	status = cfg80211_rx_mgmt(vif_ctx_lnx->netdev->ieee80211_ptr,
			 mgmt_rx_event->frequency, 
			 mgmt_rx_event->rx_signal_dbm,
			 mgmt_rx_event->frame.frame,
			 mgmt_rx_event->frame.frame_len,
			 //mgmt_rx_event->nrf_wifi_flags);
			 0);
	if (!status) {
		pr_err("%s: unregistered frame!\n", __func__);
	}
}

void nrf_wifi_cfg80211_unprot_mlme_mgmt_rx_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_umac_event_mlme *unprot_mlme_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;

	pr_info("%s: rx callback\n", __func__);
	vif_ctx_lnx = os_vif_ctx;

	cfg80211_rx_unprot_mlme_mgmt(vif_ctx_lnx->netdev,
				     unprot_mlme_event->frame.frame,
				     unprot_mlme_event->frame.frame_len);
}

void nrf_wifi_cfg80211_tx_status_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_umac_event_mlme *tx_status_event,
	unsigned int event_len)
{
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	unsigned long long host_cookie = 0;
	unsigned long long rpu_cookie = 0;
	struct cookie_info *cookie_info = NULL;
	struct cookie_info *tmp = NULL;
	bool ack_event = false;

	pr_info("%s: tx status\n", __func__);

	vif_ctx_lnx = os_vif_ctx;
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	list_for_each_entry_safe(cookie_info, tmp, &rpu_ctx_lnx->cookie_list,
				 list) {
		if (cookie_info->rpu_cookie != tx_status_event->cookie)
			continue;

		host_cookie = cookie_info->host_cookie;
		rpu_cookie = cookie_info->rpu_cookie;

		pr_err("%s: found cookie = %llu\n", __func__, host_cookie);

		list_del(&cookie_info->list);
		kfree(cookie_info);
	}

	if (host_cookie == 0)
		pr_err("cookie not found\n\n");

	ack_event = tx_status_event->nrf_wifi_flags & NRF_WIFI_EVENT_MLME_ACK ?
			    true :
			    false;
	pr_info("%s: mgmt frame %llx rpu %llx tx status: %s",
		__func__, host_cookie, rpu_cookie, ack_event ? "ACK" : "NOACK");
	cfg80211_mgmt_tx_status(vif_ctx_lnx->netdev->ieee80211_ptr, host_cookie,
				tx_status_event->frame.frame,
				tx_status_event->frame.frame_len, ack_event,
				GFP_KERNEL);
	// vif_ctx_lnx->cookie_resp = 1;
}

// void nrf_wifi_cfg80211_mgmt_tx_status_callbk_fn(void *os_vif_ctx,
// 			struct nrf_wifi_umac_event_mlme *mlme_event,
// 			unsigned int event_len)
// {
// 	pr_info("%s: callback\n", __func__);
// 	nrf_wifi_cfg80211_tx_status_callbk_fn(os_vif_ctx, mlme_event, event_len);
// }

int nrf_wifi_cfg80211_start_p2p_dev(struct wiphy *wiphy,
				    struct wireless_dev *wdev)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	int status = -1;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
	return status;
}

void nrf_wifi_cfg80211_stop_p2p_dev(struct wiphy *wiphy,
				    struct wireless_dev *wdev)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
}

int nrf_wifi_cfg80211_remain_on_channel(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					struct ieee80211_channel *chan,
					unsigned int duration, u64 *cookie)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	int if_index = -1;
	int status = -1;
	struct remain_on_channel_info *roc_info = NULL;
	struct p2p_info *p2p = NULL;

	if_index = wdev->netdev->ifindex;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	roc_info = kzalloc(sizeof(*roc_info), GFP_KERNEL);

	if (!roc_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (duration > 0)
		roc_info->dur = duration;

	roc_info->nrf_wifi_freq_params.frequency = chan->center_freq;

	p2p = &vif_ctx_lnx->p2p;
	memcpy(&p2p->remain_on_channel, chan, sizeof(*chan));

	*cookie = p2p->remain_on_channel_cookie++;
	roc_info->host_cookie = *cookie;
out:
	kfree(roc_info);

	return status;
}

void nrf_wifi_cfg80211_roc_callbk_fn(
	void *os_vif_ctx, struct nrf_wifi_event_remain_on_channel *roc_event,
	unsigned int event_len)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	unsigned long long host_cookie = 0;
	struct cookie_info *cookie_info = NULL;
	struct cookie_info *tmp = NULL;
	int match_cookie_found = 0;
	struct ieee80211_channel *chan = NULL;
	unsigned int duration = 0;

	vif_ctx_lnx = os_vif_ctx;
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	list_for_each_entry_safe(cookie_info, tmp, &rpu_ctx_lnx->cookie_list,
				 list) {
		if (cookie_info) {
			if (cookie_info->rpu_cookie != roc_event->cookie)
				continue;

			host_cookie = cookie_info->host_cookie;
			match_cookie_found = 1;

			break;
		}
	}

	if (match_cookie_found) {
		chan = ieee80211_get_channel(rpu_ctx_lnx->wiphy,
					     roc_event->frequency);

		duration = roc_event->dur;

		cfg80211_ready_on_channel(vif_ctx_lnx->wdev, host_cookie, chan,
					  duration, GFP_KERNEL);
	}
}

int nrf_wifi_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       u64 cookie)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	int if_index = -1;
	int status = -1;

	if_index = wdev->netdev->ifindex;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;
	return status;
}

void nrf_wifi_cfg80211_roc_cancel_callbk_fn(
	void *os_vif_ctx,
	struct nrf_wifi_event_remain_on_channel *roc_cancel_event,
	unsigned int event_len)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	unsigned long long host_cookie = 0;
	struct cookie_info *cookie_info = NULL;
	struct cookie_info *tmp = NULL;
	int match_cookie_found = 0;
	struct ieee80211_channel *chan = NULL;

	vif_ctx_lnx = os_vif_ctx;
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	list_for_each_entry_safe(cookie_info, tmp, &rpu_ctx_lnx->cookie_list,
				 list) {
		if (cookie_info) {
			if (cookie_info->rpu_cookie != roc_cancel_event->cookie)
				continue;
			host_cookie = cookie_info->host_cookie;
			match_cookie_found = 1;
			break;
		}

		if (match_cookie_found) {
			chan = ieee80211_get_channel(
				rpu_ctx_lnx->wiphy,
				roc_cancel_event->frequency);

			cfg80211_remain_on_channel_expired(vif_ctx_lnx->wdev,
							   host_cookie, chan,
							   GFP_KERNEL);
			list_del(&cookie_info->list);
			kfree(cookie_info);
		}
	}
}

int nrf_wifi_cfg80211_probe_client(struct wiphy *wiphy,
				   struct net_device *netdev, const u8 *peer,
				   u64 *cookie)
{
	pr_err("\n\n $$$$$$$$$$$ %s: TODO $$$$$$$$$$$$$$\n\n\n", __func__);
	return -1;
}

int nrf_wifi_cfg80211_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wow)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	int status = 0;

	rpu_ctx_lnx = wiphy_priv(wiphy);

	if (wow) {
		/* Ignoring other variable and structures in cfg80211_wowlan
		 * Not supported at UMAC level
		 */

		if (wow->rfkill_release) {
			pr_err("%s: rfkill_release is not supported by  umac\n",
			       __func__);
			goto out;
		}

		if (wow->patterns) {
			pr_err("%s: cfg80211_pkt_pattern is not supported by umac\n",
			       __func__);
			goto out;
		}

		if (wow->tcp) {
			pr_err("%s: cfg80211_wowlan_tcp is not supported by umac \n",
			       __func__);
			goto out;
		}

		if (wow->nd_config) {
			pr_err("%s: cfg80211_sched_scan_request is not supported by umac\n",
			       __func__);
			goto out;
		}
	}

out:
	return status;
}

int nrf_wifi_cfg80211_resume(struct wiphy *wiphy)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	int status = -1;

	rpu_ctx_lnx = wiphy_priv(wiphy);

	return status;
}

void nrf_wifi_cfg80211_set_wakeup(struct wiphy *wiphy, bool enabled)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;

	rpu_ctx_lnx = wiphy_priv(wiphy);

	/* We will not enable/disable wowlan here.
	 * It will be done with suspend command.
	 */

	return;
}

int nrf_wifi_cfg80211_set_power_mgmt(struct wiphy *wiphy,
				     struct net_device *netdev, bool enabled,
				     int timeout)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	int status = -1;

	rpu_ctx_lnx = wiphy_priv(wiphy);
	vif_ctx_lnx = netdev_priv(netdev);

	/* Ignoring timeout value, rpu does not support
	 * timeout value passed by upper layer
	 * it will use its own value
	 */
	status = nrf_wifi_fmac_set_power_save(rpu_ctx_lnx->rpu_ctx,
					      vif_ctx_lnx->if_idx, enabled);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_power_save failed\n", __func__);
		goto out;
	}

out:
	return status;
}

int nrf_wifi_cfg80211_set_qos_map(struct wiphy *wiphy,
				  struct net_device *netdev,
				  struct cfg80211_qos_map *qos_map)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_umac_qos_map_info *qos_map_info = NULL;
	int status = -1;

	qos_map_info = kzalloc(sizeof(*qos_map_info), GFP_KERNEL);

	if (!qos_map_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	rpu_ctx_lnx = wiphy_priv(wiphy);
	vif_ctx_lnx = netdev_priv(netdev);

	if (qos_map) {
		memcpy(&qos_map_info->qos_map_info, qos_map,
		       sizeof(struct cfg80211_qos_map));
		qos_map_info->qos_map_info_len =
			sizeof(struct cfg80211_qos_map);
	}
	status = nrf_wifi_fmac_set_qos_map(rpu_ctx_lnx->rpu_ctx,
					   vif_ctx_lnx->if_idx, qos_map_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_qos_map failed\n", __func__);
		goto out;
	}
out:
	if (qos_map_info)
		kfree(qos_map_info);

	return status;
}

static void sta_set_sinfo(struct nrf_wifi_sta_info *sta,
			  struct station_info *sinfo)
{
	if (sta->valid_fields & NRF_WIFI_STA_INFO_CONNECTED_TIME_VALID) {
		sinfo->connected_time = sta->connected_time;

		sinfo->filled |= BIT(NL80211_STA_INFO_CONNECTED_TIME);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_INACTIVE_TIME_VALID) {
		sinfo->inactive_time = sta->inactive_time;

		sinfo->filled |= BIT(NL80211_STA_INFO_INACTIVE_TIME);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_RX_BYTES_VALID) {
		sinfo->rx_bytes = sta->rx_bytes;

		sinfo->filled |= BIT(NL80211_STA_INFO_RX_BYTES);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_TX_BYTES_VALID) {
		sinfo->tx_bytes = sta->tx_bytes;

		sinfo->filled |= BIT(NL80211_STA_INFO_TX_BYTES);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_SIGNAL_VALID) {
		sinfo->signal = sta->signal;

		sinfo->filled |= BIT(NL80211_STA_INFO_SIGNAL);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_SIGNAL_AVG_VALID) {
		sinfo->signal_avg = sta->signal_avg;

		sinfo->filled |= BIT(NL80211_STA_INFO_SIGNAL_AVG);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_TX_BITRATE_VALID) {
		if (sta->tx_bitrate.nrf_wifi_flags &
		    NRF_WIFI_RATE_INFO_40_MHZ_WIDTH)
			sinfo->txrate.bw = RATE_INFO_BW_40;
		else if (sta->tx_bitrate.nrf_wifi_flags &
			 NRF_WIFI_RATE_INFO_80_MHZ_WIDTH)
			sinfo->txrate.bw = RATE_INFO_BW_80;
		else if (sta->tx_bitrate.nrf_wifi_flags &
			 NRF_WIFI_RATE_INFO_160_MHZ_WIDTH)
			sinfo->txrate.bw = RATE_INFO_BW_160;
		else
			sinfo->txrate.bw = RATE_INFO_BW_20;

		if (sta->tx_bitrate.nrf_wifi_flags &
		    NRF_WIFI_RATE_INFO_SHORT_GI)
			sinfo->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;

		if (sta->tx_bitrate.valid_fields &
		    NRF_WIFI_RATE_INFO_BITRATE_VALID)
			sinfo->txrate.legacy = sta->tx_bitrate.bitrate;

		if (sta->tx_bitrate.valid_fields &
		    NRF_WIFI_RATE_INFO_BITRATE_MCS_VALID) {
			sinfo->txrate.mcs = sta->tx_bitrate.nrf_wifi_mcs;

			sinfo->txrate.flags |= RATE_INFO_FLAGS_MCS;
		}

		if (sta->tx_bitrate.valid_fields &
		    NRF_WIFI_RATE_INFO_BITRATE_VHT_MCS_VALID) {
			sinfo->txrate.mcs = sta->tx_bitrate.vht_mcs;
			sinfo->txrate.flags |= RATE_INFO_FLAGS_VHT_MCS;
		}

		if (sta->tx_bitrate.valid_fields &
		    NRF_WIFI_RATE_INFO_BITRATE_VHT_NSS_VALID)
			sinfo->txrate.nss = sta->tx_bitrate.vht_nss;

		sinfo->filled |= BIT(NL80211_STA_INFO_TX_BITRATE);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_RX_BITRATE_VALID) {
		if (sta->rx_bitrate.nrf_wifi_flags &
		    NRF_WIFI_RATE_INFO_40_MHZ_WIDTH)
			sinfo->rxrate.bw = RATE_INFO_BW_40;
		else if (sta->rx_bitrate.nrf_wifi_flags &
			 NRF_WIFI_RATE_INFO_80_MHZ_WIDTH)
			sinfo->rxrate.bw = RATE_INFO_BW_80;
		else if (sta->rx_bitrate.nrf_wifi_flags &
			 NRF_WIFI_RATE_INFO_160_MHZ_WIDTH)
			sinfo->rxrate.bw = RATE_INFO_BW_160;
		else
			sinfo->rxrate.bw = RATE_INFO_BW_20;

		if (sta->rx_bitrate.nrf_wifi_flags &
		    NRF_WIFI_RATE_INFO_SHORT_GI)
			sinfo->rxrate.flags |= RATE_INFO_FLAGS_SHORT_GI;

		if (sta->rx_bitrate.valid_fields &
		    NRF_WIFI_RATE_INFO_BITRATE_VALID)
			sinfo->rxrate.legacy = sta->rx_bitrate.bitrate;

		if (sta->rx_bitrate.valid_fields &
		    NRF_WIFI_RATE_INFO_BITRATE_MCS_VALID) {
			sinfo->rxrate.mcs = sta->rx_bitrate.nrf_wifi_mcs;
			sinfo->rxrate.flags |= RATE_INFO_FLAGS_MCS;
		}

		if (sta->rx_bitrate.nrf_wifi_flags &
		    NRF_WIFI_RATE_INFO_BITRATE_VHT_MCS_VALID) {
			sinfo->rxrate.mcs = sta->rx_bitrate.vht_mcs;
			sinfo->rxrate.flags |= RATE_INFO_FLAGS_VHT_MCS;
		}

		if (sta->rx_bitrate.nrf_wifi_flags &
		    NRF_WIFI_RATE_INFO_BITRATE_VHT_NSS_VALID)
			sinfo->rxrate.nss = sta->rx_bitrate.vht_nss;

		sinfo->filled |= BIT(NL80211_STA_INFO_RX_BITRATE);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_STA_FLAGS_VALID) {
		sinfo->sta_flags.mask = sta->sta_flags.nrf_wifi_mask;
		sinfo->sta_flags.set = sta->sta_flags.nrf_wifi_set;

		sinfo->filled |= BIT(NL80211_STA_INFO_STA_FLAGS);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_LLID_VALID) {
		sinfo->llid = sta->llid;

		sinfo->filled |= BIT(NL80211_STA_INFO_LLID);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_PLID_VALID) {
		sinfo->plid = sta->plid;

		sinfo->filled |= BIT(NL80211_STA_INFO_PLID);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_PLINK_STATE_VALID) {
		sinfo->plink_state = sta->plink_state;

		sinfo->filled |= BIT(NL80211_STA_INFO_PLINK_STATE);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_RX_PACKETS_VALID) {
		sinfo->rx_packets = sta->rx_packets;

		sinfo->filled |= BIT(NL80211_STA_INFO_RX_PACKETS);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_TX_PACKETS_VALID) {
		sinfo->tx_packets = sta->tx_packets;

		sinfo->filled |= BIT(NL80211_STA_INFO_TX_PACKETS);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_TX_RETRIES_VALID) {
		sinfo->tx_retries = sta->tx_retries;

		sinfo->filled |= BIT(NL80211_STA_INFO_TX_RETRIES);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_TX_FAILED_VALID) {
		sinfo->tx_failed = sta->tx_failed;

		sinfo->filled |= BIT(NL80211_STA_INFO_TX_FAILED);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_EXPECTED_THROUGHPUT_VALID) {
		sinfo->expected_throughput = sta->expected_throughput;

		sinfo->filled |= BIT(NL80211_STA_INFO_EXPECTED_THROUGHPUT);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_BEACON_LOSS_COUNT_VALID) {
		sinfo->beacon_loss_count = sta->beacon_loss_count;

		sinfo->filled |= BIT(NL80211_STA_INFO_BEACON_LOSS);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_LOCAL_PM_VALID) {
		sinfo->local_pm = sta->local_pm;

		sinfo->filled |= BIT(NL80211_STA_INFO_LOCAL_PM);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_PEER_PM_VALID) {
		sinfo->peer_pm = sta->peer_pm;

		sinfo->filled |= BIT(NL80211_STA_INFO_PEER_PM);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_NONPEER_PM_VALID) {
		sinfo->nonpeer_pm = sta->nonpeer_pm;

		sinfo->filled |= BIT(NL80211_STA_INFO_NONPEER_PM);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_T_OFFSET_VALID) {
		sinfo->t_offset = sta->t_offset;

		sinfo->filled |= BIT(NL80211_STA_INFO_T_OFFSET);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_RX_DROPPED_MISC_VALID) {
		sinfo->rx_dropped_misc = sta->rx_dropped_misc;

		sinfo->filled |= BIT(NL80211_STA_INFO_RX_DROP_MISC);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_RX_BEACON_VALID) {
		sinfo->rx_beacon = sta->rx_beacon;

		sinfo->filled |= BIT(NL80211_STA_INFO_BEACON_RX);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_RX_BEACON_SIGNAL_AVG_VALID) {
		sinfo->rx_beacon_signal_avg = sta->rx_beacon_signal_avg;

		sinfo->filled |= BIT(NL80211_STA_INFO_BEACON_SIGNAL_AVG);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_STA_BSS_PARAMS_VALID) {
		sinfo->bss_param.flags = sta->bss_param.nrf_wifi_flags;
		sinfo->bss_param.dtim_period = sta->bss_param.dtim_period;
		sinfo->bss_param.beacon_interval =
			sta->bss_param.beacon_interval;

		sinfo->filled |= BIT(NL80211_STA_INFO_BSS_PARAM);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_CHAIN_SIGNAL_VALID) {
		memcpy(sinfo->chain_signal, sta->chain_signal,
		       sizeof(sinfo->chain_signal));

		sinfo->filled |= BIT(NL80211_STA_INFO_CHAIN_SIGNAL);
	}

	if (sta->valid_fields & NRF_WIFI_STA_INFO_CHAIN_SIGNAL_AVG_VALID) {
		memcpy(sinfo->chain_signal_avg, sta->chain_signal_avg,
		       sizeof(sinfo->chain_signal_avg));

		sinfo->filled |= BIT(NL80211_STA_INFO_CHAIN_SIGNAL_AVG);
	}
}

int nrf_wifi_cfg80211_get_station(struct wiphy *wiphy, struct net_device *dev,
				  const u8 *mac, struct station_info *sinfo)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	unsigned int count = 50;
	int status = 0;
	pr_info("%s: Get station\n", __func__);

	vif_ctx_lnx = netdev_priv(dev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	status = nrf_wifi_fmac_get_station(rpu_ctx_lnx->rpu_ctx,
					   vif_ctx_lnx->if_idx, (void *)mac);
	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_get_station failed\n", __func__);
		return -EIO;
	}

	pr_debug("%s: Waiting for response from RPU (Get STA)\n", __func__);

	while (!vif_ctx_lnx->station_info && (count-- > 0))
		msleep_interruptible(100);

	if (!vif_ctx_lnx->station_info) {
		pr_err("%s:Timed out waiting for response from RPU (Get STA) \n",
		       __func__);
		return -ETIMEDOUT;
	}

	sta_set_sinfo(vif_ctx_lnx->station_info, sinfo);

	kfree(vif_ctx_lnx->station_info);

	vif_ctx_lnx->station_info = NULL;

	return 0;
}

int nrf_wifi_cfg80211_get_tx_power(struct wiphy *wiphy,
				   struct wireless_dev *wdev, int *dbm)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	unsigned int count = 500;
	int status = 0;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	vif_ctx_lnx->event_tx_power = 0;

	if (!(wdev->netdev->flags & IFF_UP)) {
		pr_debug("%s: Interface is not UP\n", __func__);
		return -ENETDOWN;
	}

	status = nrf_wifi_fmac_get_tx_power(rpu_ctx_lnx->rpu_ctx,
					    vif_ctx_lnx->if_idx);
	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_get_tx_power failed\n", __func__);
		return -EIO;
	}

	pr_debug("%s: Waiting for response from RPU (Get TX power)\n",
		 __func__);

	while (!vif_ctx_lnx->event_tx_power && (count-- > 0))
		msleep_interruptible(100);

	if (!vif_ctx_lnx->event_tx_power) {
		pr_err("%s:Timed out waiting for response from RPU (Set TX power) \n",
		       __func__);
		return -ETIMEDOUT;
	}

	*dbm = vif_ctx_lnx->tx_power;

	vif_ctx_lnx->tx_power = 0;

	return 0;
}

int nrf_wifi_cfg80211_get_channel(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  struct cfg80211_chan_def *chandef)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_fmac_vif_ctx_lnx *vif_ctx_lnx = NULL;
	struct nrf_wifi_fmac_dev_ctx_def *def_dev_ctx = NULL;
	struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx = NULL;
	unsigned int count = 500;
	unsigned int channel = 0;
	int status = 0;

	vif_ctx_lnx = netdev_priv(wdev->netdev);
	rpu_ctx_lnx = vif_ctx_lnx->rpu_ctx;

	if (!(wdev->netdev->flags & IFF_UP)) {
		pr_debug("%s: Interface is not UP\n", __func__);
		return -ENETDOWN;
	}
	
	if (wdev->iftype == NL80211_IFTYPE_MONITOR) {
		fmac_dev_ctx = rpu_ctx_lnx->rpu_ctx;
		def_dev_ctx = wifi_dev_priv(fmac_dev_ctx);

		channel = def_dev_ctx->vif_ctx[vif_ctx_lnx->if_idx]->channel;
		if (channel >= 14) {
			chandef->chan = ieee80211_get_channel(
				wiphy, band_5ghz.channels[channel - 14].center_freq);
		} else {
			chandef->chan = ieee80211_get_channel(
				wiphy, band_2ghz.channels[channel].center_freq);
		}

		chandef->width = 1;
		chandef->center_freq1 = chandef->chan->center_freq;
		chandef->center_freq2 = 0;

		goto out;
	}

	status = nrf_wifi_fmac_get_channel(rpu_ctx_lnx->rpu_ctx,
					   vif_ctx_lnx->if_idx);
	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_get_channel failed\n", __func__);
		return -EIO;
	}

	pr_debug("%s: Waiting for response from RPU (Get Channel)\n", __func__);

	while (!vif_ctx_lnx->chan_def && (count-- > 0))
		msleep_interruptible(100);

	if (!vif_ctx_lnx->chan_def) {
		status = -ETIMEDOUT;
		pr_err("%s:Timed out waiting for response from RPU (Get Channel)\n",
		       __func__);
		goto out;
	}

	if (vif_ctx_lnx->chan_def->chan.center_frequency == 0) {
		status = -ENODATA;
		goto out;
	}

	chandef->chan = ieee80211_get_channel(
		wiphy, vif_ctx_lnx->chan_def->chan.center_frequency);

	chandef->width = vif_ctx_lnx->chan_def->width;
	chandef->center_freq1 = vif_ctx_lnx->chan_def->center_frequency1;
	chandef->center_freq2 = vif_ctx_lnx->chan_def->center_frequency2;

out:
	if (vif_ctx_lnx->chan_def) {
		kfree(vif_ctx_lnx->chan_def);
		vif_ctx_lnx->chan_def = NULL;
	}

	return status;
}

int nrf_wifi_cfg80211_set_wiphy_params(struct wiphy *wiphy,
				       unsigned int changed)
{
	struct nrf_wifi_ctx_lnx *rpu_ctx_lnx = NULL;
	struct nrf_wifi_umac_set_wiphy_info *wiphy_info = NULL;
	int status = -1;

	rpu_ctx_lnx = wiphy_priv(wiphy);
	wiphy_info = kzalloc(sizeof(*wiphy_info), GFP_KERNEL);

	if (!wiphy_info) {
		pr_err("%s: Unable to allocate memory\n", __func__);
		goto out;
	}

	if (changed & WIPHY_PARAM_RTS_THRESHOLD)
		wiphy_info->rts_threshold = wiphy->rts_threshold;
	if (changed & WIPHY_PARAM_FRAG_THRESHOLD)
		wiphy_info->frag_threshold = wiphy->frag_threshold;
	if (changed & WIPHY_PARAM_RETRY_LONG)
		wiphy_info->retry_long = wiphy->retry_long;
	if (changed & WIPHY_PARAM_RETRY_SHORT)
		wiphy_info->retry_short = wiphy->retry_short;

	status = nrf_wifi_fmac_set_wiphy_params(
		rpu_ctx_lnx->rpu_ctx, rpu_ctx_lnx->def_vif_ctx->if_idx,
		wiphy_info);

	if (status == NRF_WIFI_STATUS_FAIL) {
		pr_err("%s: nrf_wifi_fmac_set_wiphy failed\n", __func__);
		goto out;
	}

out:
	if (wiphy_info)
		kfree(wiphy_info);

	return status;
}

struct cfg80211_ops cfg80211_ops = {

	.add_virtual_intf = nrf_wifi_cfg80211_add_vif,
	.del_virtual_intf = nrf_wifi_cfg80211_del_vif,
	.change_virtual_intf = nrf_wifi_cfg80211_chg_vif,

	.add_key = nrf_wifi_cfg80211_add_key,
	.del_key = nrf_wifi_cfg80211_del_key,
	.set_default_key = nrf_wifi_cfg80211_set_def_key,
	.set_default_mgmt_key = nrf_wifi_cfg80211_set_def_mgmt_key,

	.start_ap = nrf_wifi_cfg80211_start_ap,
	.change_beacon = nrf_wifi_cfg80211_chg_bcn,
	.stop_ap = nrf_wifi_cfg80211_stop_ap,
	.connect = nrf_wifi_cfg80211_connect,
	.disconnect = nrf_wifi_cfg80211_disconnect,

	.add_station = nrf_wifi_cfg80211_add_sta,
	.del_station = nrf_wifi_cfg80211_del_sta,
	.change_station = nrf_wifi_cfg80211_chg_sta,
	.change_bss = nrf_wifi_cfg80211_chg_bss,
	// .set_txq_params = nrf_wifi_cfg80211_set_txq_params,

	.set_monitor_channel = nrf_wifi_cfg80211_set_monitor_channel,
	.scan = nrf_wifi_cfg80211_scan,
	.auth = nrf_wifi_cfg80211_auth,
	.assoc = nrf_wifi_cfg80211_assoc,
	.deauth = nrf_wifi_cfg80211_deauth,
	.disassoc = nrf_wifi_cfg80211_disassoc,
	.mgmt_tx = nrf_wifi_cfg80211_mgmt_tx,
	.update_mgmt_frame_registrations = nrf_wifi_cfg80211_mgmt_frame_reg,
	// .start_p2p_device = nrf_wifi_cfg80211_start_p2p_dev,
	// .stop_p2p_device = nrf_wifi_cfg80211_stop_p2p_dev,
	.remain_on_channel = nrf_wifi_cfg80211_remain_on_channel,
	.cancel_remain_on_channel = nrf_wifi_cfg80211_cancel_remain_on_channel,

	.probe_client = nrf_wifi_cfg80211_probe_client,

	.suspend = nrf_wifi_cfg80211_suspend,
	.resume = nrf_wifi_cfg80211_resume,
	.set_wakeup = nrf_wifi_cfg80211_set_wakeup,
	.set_power_mgmt = nrf_wifi_cfg80211_set_power_mgmt,
	.set_qos_map = nrf_wifi_cfg80211_set_qos_map,

	.get_station = nrf_wifi_cfg80211_get_station,
	.get_tx_power = nrf_wifi_cfg80211_get_tx_power,
	.get_channel = nrf_wifi_cfg80211_get_channel,
	.set_wiphy_params = nrf_wifi_cfg80211_set_wiphy_params,
};
#else /* CONFIG_NRF700X_RADIO_TEST */
struct cfg80211_ops cfg80211_ops = {};
#endif /* !CONFIG_NRF700X_RADIO_TEST */

static const u32 cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,		WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_CCMP_256,	WLAN_CIPHER_SUITE_AES_CMAC,
	WLAN_CIPHER_SUITE_GCMP,		WLAN_CIPHER_SUITE_GCMP_256,
	WLAN_CIPHER_SUITE_BIP_GMAC_128, WLAN_CIPHER_SUITE_BIP_GMAC_256,
	WLAN_CIPHER_SUITE_BIP_CMAC_256,
};

static void setup_vht_cap(struct ieee80211_sta_vht_cap *vht_info)
{
	vht_info->vht_supported = true;
	vht_info->cap =
		IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454 |
		/*64KB Rx buffer size*/
		(3 << IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT) |
		IEEE80211_VHT_CAP_SHORT_GI_80 | IEEE80211_VHT_CAP_RXLDPC |
		IEEE80211_VHT_CAP_TXSTBC | IEEE80211_VHT_CAP_RXSTBC_1 |
		IEEE80211_VHT_CAP_HTC_VHT;

	/* 1x1 */
	vht_info->vht_mcs.rx_mcs_map =
		((IEEE80211_VHT_MCS_SUPPORT_0_7) << (2 * 0)) |
		((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2 * 1)) |
		((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2 * 2)) |
		((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2 * 3)) |
		((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2 * 4)) |
		((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2 * 5)) |
		((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2 * 6)) |
		((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2 * 7));

	vht_info->vht_mcs.tx_mcs_map = vht_info->vht_mcs.rx_mcs_map;
}

static void setup_ht_cap(struct ieee80211_sta_ht_cap *ht_info)
{
	ht_info->ht_supported = true;

	ht_info->cap = 0;
	ht_info->cap |= IEEE80211_HT_CAP_MAX_AMSDU;
	/* Advertise SGI support only if the RPU supports it */
	ht_info->cap |= IEEE80211_HT_CAP_SGI_20;
	ht_info->cap |= IEEE80211_HT_CAP_SGI_40;
	ht_info->cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;

	ht_info->cap |= (1 << IEEE80211_HT_CAP_RX_STBC_SHIFT);
	ht_info->cap |= IEEE80211_HT_CAP_LSIG_TXOP_PROT;

	ht_info->ampdu_factor = IEEE80211_HT_MAX_AMPDU_32K;
	ht_info->ampdu_density = IEEE80211_HT_MPDU_DENSITY_16;

	ht_info->mcs.tx_params |= IEEE80211_HT_MCS_TX_DEFINED;
	ht_info->mcs.rx_mask[0] = 0xff;
	ht_info->mcs.rx_mask[4] = 0x1;
}

static const struct ieee80211_sband_iftype_data he_capa_2ghz = {
	.types_mask = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP),
	.he_cap = {
		.has_he = true,
		.he_cap_elem = {
			.mac_cap_info[0] =
				IEEE80211_HE_MAC_CAP0_HTC_HE,
		},
		.he_mcs_nss_supp = {
			.rx_mcs_80 = cpu_to_le16(0xfffc),
			.tx_mcs_80 = cpu_to_le16(0xfffc),
			.rx_mcs_160 = cpu_to_le16(0xffff),
			.tx_mcs_160 = cpu_to_le16(0xffff),
			.rx_mcs_80p80 = cpu_to_le16(0xffff),
			.tx_mcs_80p80 = cpu_to_le16(0xffff),
		},
	},
};

static const struct ieee80211_sband_iftype_data he_capa_5ghz = {
	.types_mask = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP),
	.he_cap = {
		.has_he = true,
		.he_cap_elem = {
			.mac_cap_info[0] =
				IEEE80211_HE_MAC_CAP0_HTC_HE,
		},
		.he_mcs_nss_supp = {
			.rx_mcs_80 = cpu_to_le16(0xfffc),
			.tx_mcs_80 = cpu_to_le16(0xfffc),
			.rx_mcs_160 = cpu_to_le16(0xffff),
			.tx_mcs_160 = cpu_to_le16(0xffff),
			.rx_mcs_80p80 = cpu_to_le16(0xffff),
			.tx_mcs_80p80 = cpu_to_le16(0xffff),
		},
	},
};

static void setup_he_cap(struct ieee80211_supported_band *sband)
{
	if (sband->band == NL80211_BAND_2GHZ)
		sband->iftype_data =
			(struct ieee80211_sband_iftype_data *)&he_capa_2ghz;
	else if (sband->band == NL80211_BAND_5GHZ)
		sband->iftype_data =
			(struct ieee80211_sband_iftype_data *)&he_capa_5ghz;
	else
		return;

	sband->n_iftype_data = 1;
}

void wiphy_init(struct wiphy *wiphy)
{
	wiphy->bands[NL80211_BAND_2GHZ] = &band_2ghz;
	wiphy->bands[NL80211_BAND_5GHZ] = &band_5ghz;
	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
	setup_ht_cap(&wiphy->bands[NL80211_BAND_2GHZ]->ht_cap);
	setup_ht_cap(&wiphy->bands[NL80211_BAND_5GHZ]->ht_cap);
	setup_vht_cap(&wiphy->bands[NL80211_BAND_5GHZ]->vht_cap);
	setup_he_cap(wiphy->bands[NL80211_BAND_2GHZ]);
	setup_he_cap(wiphy->bands[NL80211_BAND_5GHZ]);

	wiphy->interface_modes =
		BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP) |
		// BIT(NL80211_IFTYPE_P2P_GO) | BIT(NL80211_IFTYPE_P2P_CLIENT) |
		BIT(NL80211_IFTYPE_MONITOR);

	wiphy->software_iftypes |= BIT(NL80211_IFTYPE_MONITOR);
	// wiphy->software_iftypes |= BIT(NL80211_IFTYPE_AP);

	wiphy->iface_combinations = iface_combinations;
	wiphy->n_iface_combinations = 1;

	wiphy->max_scan_ssids = 4;
	wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;

	wiphy->cipher_suites = cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(cipher_suites);
}

struct wiphy *cfg80211_if_init(struct device* dev)
{
	struct wiphy *wiphy = NULL;

	/* Create the radio interface */
	wiphy = wiphy_new_nm(&cfg80211_ops, sizeof(struct nrf_wifi_ctx_lnx),
			     NULL);

	wiphy->mgmt_stypes = ieee80211_default_mgmt_stypes;

	wiphy->max_remain_on_channel_duration = 5000;

	wiphy->flags |= WIPHY_FLAG_NETNS_OK | WIPHY_FLAG_4ADDR_AP |
			WIPHY_FLAG_4ADDR_STATION | WIPHY_FLAG_REPORTS_OBSS |
			WIPHY_FLAG_OFFCHAN_TX |
			WIPHY_FLAG_CONTROL_PORT_PROTOCOL | WIPHY_FLAG_AP_UAPSD |
			WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;

	wiphy->features |=
		NL80211_FEATURE_SK_TX_STATUS | //NL80211_FEATURE_SAE |
		NL80211_FEATURE_HT_IBSS | NL80211_FEATURE_VIF_TXPOWER |
		NL80211_FEATURE_MAC_ON_CREATE | NL80211_FEATURE_USERSPACE_MPM;

	/* Below flag is required for passing duration by iw utilities */
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_SET_SCAN_DWELL);
	
	set_wiphy_dev(wiphy, dev);

	wiphy_init(wiphy);

	if (wiphy_register(wiphy) < 0) {
		pr_err("%s: Cannot register wiphy device\n", __func__);
		wiphy_free(wiphy);
		wiphy = NULL;
		goto out;
	}

out:
	return wiphy;
}

void cfg80211_if_deinit(struct wiphy *wiphy)
{
	wiphy_unregister(wiphy);
	wiphy_free(wiphy);
}
