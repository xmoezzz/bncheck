* 这里误报的原因是free函数识别
* 理想情况下是，我们判断如果一个函数`func(a1, a2)`, 从他的入口点开始，除了if(a2 == NULL)的路径上都`free(a2)`，那么就判定为func(a1, a2)会deallocate a2
	* 这里应该是做flow-path-sensitive dataflow
	* 但是显然我们没有这个框架- - 
	* 所以这里的做法是找到每个free之后，检查他们的分支依赖（`branch_depandence`）, 如果 free1(a2)依赖分支1的true, free2(a2)依赖分支1的true，那么我们就判定分支1对a2是否被free没有影响。
	* 最后如果只剩下`a2 == NULL`类型的分支，就判定func(a1, a2) deallocate了a2

* 这里的误报是类似这样的
```c
void talk_off(int condition1, int condition2, void * target) {
	if (condition1) {
		if (condition2) {
			free(target)
		}
	}
	else {
		if (condition2) {
			free(target)
		}
	}
}
```

这里的`free(target)` 被编译器合并成一个，导致CFG如下
```
						condition1
						/		\
					con2       con2`
					/	 \	/		\
				  ret    free      ret
```
最后的结果就是free没有任何一个`branch_depandece`


