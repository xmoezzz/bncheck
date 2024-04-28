* `https://github.com/ejurgensen/forked-daapd/commit/bdd6bab9824be4b440f43ddea4749caf2b284a9d#diff-06a9a1dea0928f303cbe80be6ca4fc9aL1031`

```c
unsigned __int64 __fastcall sub_411850(char *haystack, unsigned int a2)
{
	...
	{
		v23 = snprintf(&filename, 0x1000uLL, "%s", v14);
		free(v14);
		if ( v23 <= 0xFFF )
		{
			v7 = stat_buf.st_mode & 0xF000;
			goto LABEL_17;
		}
		sub_410370(1, (char *)8, "Skipping %s, PATH_MAX exceeded\n", v14);
	}
	...
}
```
