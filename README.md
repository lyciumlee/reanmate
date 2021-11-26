# reanmate
android kernel with reverse engineering infrastructures
reanmate 是一个为了 android 逆向工程的定制的内核。
# what is the reanmate
reanmate is the abbreviation for reverse android application mate.
reanmate 是安卓逆向程序伴侣的简称
# reanmate functions / 功能
reanmate add an syscall to help reverse engineers to hide their tools process，hide their tools tcp ports，log application syscall invocations and hide injection module from /proc/self/maps.
reanmate通过添加syscall的方式，可以通过使用syscall来达到内核级隐藏调试器进程、调试器网络端口、记录syscall调用、隐藏注入的调试器模块。

reanmate always set tracer pid zero, and modify process trace status to sleeping. It also modify the wchan function to hide the debug status.
reanmate也将被调试程序的调试程序pid设置为0，程序将不会在proc目录显示被调试状态。

# how to use / 使用说明
reanmate will use the same way with Google management for android sources. The branch name contain the source branch name and system id. If you want to compile the kernel, you should init your AOSP and set your kernel compile environment correctly.
reanmate 将采用和 Google 管理 android 源代码的一样的方式来管理内核源码。仓库的分支名含有 Google 官方源代码的分支名称和系统代号。如果你想自己编译这个内核，你需要自行初始化AOSP，并且正确的设置你的编译环境。

