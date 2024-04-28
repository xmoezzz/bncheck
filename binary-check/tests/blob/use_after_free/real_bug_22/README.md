* `r2/Routers/done/dlink/901de964099cbd3ffcaa1403c822b8154bbc064b/squashfs-root-1/lib/libupnp.so.2.0.1`


		int __fastcall sub_77E4(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int (__fastcall *a9)(int))
		{
          ...
		  if ( !v12 )
		  {
			v12 = sub_4CE0((int)v11);
			if ( v12 )
			{
			  free(v11);
			  shutdown(*v11, 2);
			  close(*v11);
			  shutdown(v11[1], 2);
			  close(v11[1]);
			  return v12;
			}
