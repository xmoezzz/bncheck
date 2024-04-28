*  `r2/Routers/done/dlink/901de964099cbd3ffcaa1403c822b8154bbc064b/squashfs-root-1/lib/libAuth.so`
* `0x44D34`

		int __fastcall krb5_random_key(int a1, int a2, int a3, _DWORD *a4, int a5, int a6, int a7, int a8, int a9, int (__fastcall *a10)(int)) //0x44D34
		{
		  int v10; // r6
		  int v11; // r5
		  _DWORD *v12; // r7
		  void *v13; // r4
		  int v14; // r5

		  v10 = a1;
		  v11 = a2;
		  v12 = a4;
		  v13 = malloc(0x10u);
		  if ( !v13 )
			return 12;
		  v14 = j_krb5_c_make_random_key(v10, *(_DWORD *)(v11 + 4), (int)v13);
		  if ( v14 )
			free(v13);
		  *v12 = v13;
		  return v14;
		}
