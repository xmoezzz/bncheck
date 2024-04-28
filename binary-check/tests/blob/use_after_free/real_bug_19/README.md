* `/mnt/disk1/zhao/r1/done/3159d7d8132036adebd093014c8b57a0ff768f70/N300-V1.1.0.46_1.0.1.img.extracted/squashfs-root-0/usr/sbin/openl2tpd`
* 主线没修，代码从2010年不再维护
* 地址`0x41AE98`

		static struct l2tp_peer_profile *l2tp_peer_profile_alloc(char *name)
		{
			struct l2tp_peer_profile *profile;

			profile = calloc(1, sizeof(struct l2tp_peer_profile));
			if (profile == NULL) {
				l2tp_stats.no_peer_resources++;
				goto error;
			}
			profile->profile_name = strdup(name);
			if (profile->profile_name == NULL) {
				l2tp_stats.no_peer_resources++;
				goto error;
			}

			/* Fill with defaults */
			profile->we_can_be_lac = l2tp_peer_profile_default->we_can_be_lac;
			profile->we_can_be_lns = l2tp_peer_profile_default->we_can_be_lns;
			profile->default_tunnel_profile_name = strdup(l2tp_peer_profile_default->default_tunnel_profile_name);
			profile->default_session_profile_name = strdup(l2tp_peer_profile_default->default_session_profile_name);
			profile->default_ppp_profile_name = strdup(l2tp_peer_profile_default->default_ppp_profile_name);
			if ((profile->default_tunnel_profile_name == NULL) ||
				(profile->default_session_profile_name == NULL) ||
				(profile->default_ppp_profile_name == NULL)) {
				l2tp_stats.no_peer_resources++;
				goto error;
			}
			profile->netmask.s_addr = INADDR_BROADCAST;
			profile->netmask_len = 32;

			USL_LIST_HEAD_INIT(&profile->list);

		out:
			return profile;

		error:
			if (profile != NULL) {
				l2tp_peer_profile_free(profile);
			}

			goto out;
		}
