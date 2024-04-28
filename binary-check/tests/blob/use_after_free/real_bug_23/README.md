* `r2/Routers/done/netgear/0802598e8a452337ac2f3d884b23e36a1f41ac35/ReadyNASOS-6.7.1-arm.img.extracted/cpio-root-0/usr/bin/sensors`

		int __fastcall sub_11C04(int a1, char **a2, double a3)
		{
		  v19 = a2;
		  v20 = a3;
		  v3 = a1;
		  v18 = 0;
		  while ( 1 )
		  {
			v11 = (char *)v10;
			if ( v10 )
			{
			  printf("%s:\n", v10);
			  free(v11);
			  v19 = 0;
			  while ( 1 )
			  {
				v12 = sensors_get_all_subfeatures(v3, v7, &v19);
				v13 = (const char **)v12;
				if ( !v12 )
				  break;
				...
				if (...) {
				}
				else {
					printf("%s\n", v11);
				}

				
