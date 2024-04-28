* `https://github.com/wbx-github/uclibc-ng/blob/3538ba34e0e415105d3fe235605e6dba1597ad98/libc/misc/ftw/ftw.c#L305`
* 这个binary的问题函数是`sub_12654`

		while ((d = __readdir64 (st)) != NULL)
		{
			size_t this_len = NAMLEN (d);
			if (actsize + this_len + 2 >= bufsize)
			{
				char *newp;
				bufsize += MAX (1024, 2 * this_len);
				newp = (char *) realloc (buf, bufsize);
				if (newp == NULL)
				{
					/* No more memory.  */
					int save_err = errno;
					free (buf); //FREE....
					__set_errno (save_err);
					result = -1;
					break;
				}
				buf = newp;
			}

			*((char *) __mempcpy (buf + actsize, d->d_name, this_len))
				= '\0';
			actsize += this_len + 1;
		}

		/* Terminate the list with an additional NUL byte.  */
		buf[actsize++] = '\0';//USE

		/* Shrink the buffer to what we actually need.  */
		data->dirstreams[data->actdir]->content = realloc (buf, actsize); //USE
