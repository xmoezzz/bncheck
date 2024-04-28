* `r1/done/82c518a4921ab60b5d76793ee7f6ee8f30f5b238/WNR3500Lv2-V1.2.0.50_50.0.90.chk.extracted/squashfs-root-0/usr/sbin/bftpd`
* 至少在2014年已经修复

		int bftpd_cwd_chdir() //0x409C44
		{
		  ....
		  if ( strncmp(v0, "/shares", 7u) && strcmp(v0, &byte_412964) )
		  {
			free(v0);
			bftpd_log("Block cwd to '%s'\n", v0);
			...
		  }
		  ....
		}

			
