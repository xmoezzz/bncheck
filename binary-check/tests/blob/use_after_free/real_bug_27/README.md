* `/mnt/disk1/zhao/r2/Routers/done/trendnet/c28025839a966fc8458e9f58e24ceb35c1e2d3db/TEW722BRM_vA1_8M_V1.02.B08_20151204.img.extracted/squashfs-root/apps/ecmh`

		void sub_40A5FC() {
          ...
		  if ( *(int *)v12 < 0 && *(_DWORD *)&v12[4] )
		  {
			v8 = *_errno_location();
			free(*(void **)&v12[4]);
			*_errno_location() = v8;
		  }
		  result = *(_QWORD *)v12;
		  *v21 = *(_DWORD *)&v12[4];
		  return result;
		}
