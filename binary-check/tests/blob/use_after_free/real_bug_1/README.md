* FIX: `https://github.com/guillemj/dpkg/commit/72f4e49f965e8860d541bec7fea814d2cea85c81`
* `r2/Routers/done/netgear/6b7d91379f5f63b757a98c3ccbc17db507213c0c/ReadyNASOS-V6.0.1/ReadyNASOS-6.0.1-arm.img.extracted/root-fs/usr/bin/dpkg`

```c
void sub_1E1E0(int a1, int a2, int a3, int a4, int a5, ...)
{
	void *v5; // r5
	FILE *v6; // r4
	char v7; // [sp+4h] [bp-814h]

	v5 = (void *)sub_1F0B0("arch");
	v6 = (FILE *)fopen64(v5, "r");
	free(v5);
	if ( v6 )
	{
		while ( sub_2ADA4(&v7, 2048, v6, (int)v5) >= 0 )
			sub_1E158(&v7);
		fclose(v6);
	}
	else
	{
		byte_C46BE = 1;
	}
}
```
