* `r1/done/3159d7d8132036adebd093014c8b57a0ff768f70/N300-V1.1.0.46_1.0.1.img.extracted/squashfs-root-0/lib/libzebra.so.0`
* 主线已经修复
* 函数:`0x2136C`

		int __fastcall sub_2136C(int a1, int a2, int a3, const char **a4)
		{
		  int v4; // s2
		  int v5; // v0
		  const char **v6; // s0
		  int v7; // s1
		  const char *v8; // a3
		  int result; // v0
		  int v10; // s0
		  void (__fastcall *v11)(int); // t9

		  v4 = a2;
		  v6 = a4;
		  v5 = access_list_lookup(1, *a4);
		  v7 = v5;
		  if ( v5 )
		  {
			v10 = *(_DWORD *)(v5 + 8);
			sub_1F834(v5);                              // free
			v11 = *(void (__fastcall **)(int))(v10 + 20);
			if ( v11 )
			  v11(v7);
			result = 0;
		  }
		  else
		  {
			v8 = (const char *)&off_3CEE8;
			if ( *(_DWORD *)(v4 + 4) )
			  v8 = "\n";
			vty_out(v4, "%% access-list %s doesn't exist%s", *v6, v8);
			result = 1;
		  }
		  return result;
		}
