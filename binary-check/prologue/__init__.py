"""和analysis中的不同, prologue中的插件要严格按照顺序来执行
   prologue中的插件不暴露给外界调用
   外界通过调用prologue_main中的接口进行各种初始化
   不可避免的，在prologue中会调用analysis中的一些分析器，
   所以在分析完成之后一定要清理analysis中的缓存
"""


