# L4D2-Lan-over-IPv6  
求生之路2 IPv6局域网对战工具 
  
Test platform:  
os:Windows 8.1 64bit and Windows 10 64bit  
game:Left4dead2 V2121  
  
Usage:  
1、compile it or use the dll I provided,you may need VC2015 runtime environment.  
2、create v4v6map.txt and put it on the root path of l4d2.  
3、inject it into left4dead2.exe,if you don't have an injector,just find "DllInjection_CreateRemoteThread" repo on my github to get one,don't forget to change the dll filename when you compile my injector and please run the injector as administrator.   
4、after the server started a game,for clients,use "connect xxx.xxx.xxx.xxx(the IPv4 address of server in v4v6map.txt)" to connect the server.As v4v6map.txt given below,use "connect 172.16.0.1".  
  
使用方法：  
1、编译dll或者使用我提供的，你需要安装VC2015运行时环境  
2、创建 v4v6map.txt 并放到求生之路2的根目录下  
3、注入dll，如果你没有注入器，可以使用我提供的，使用管理员权限运行"injector.exe left4dead2.exe"即可  
4、在服务端创建游戏之后，客户端使用"connect xxx.xxx.xxx.xxx(v4v6map.txt里写的服务端IPv4地址)"来连接到服务器。举个栗子，如果是下面的实例v4v6map.txt，输入"connect 172.16.0.1"即可  
  
  
About v4v6map.txt:  
suppose that 2001:xxxx::1 is the server IP,2001:xxxx::2-4 are clients'  
server's v4v6map.txt:  
172.16.0.2  2001:xxxx::2  
172.16.0.3  2001:xxxx::3  
172.16.0.4  2001:xxxx::4  
  
client's v4v6map.txt:  
172.16.0.1  2001:xxxx::1  
  
The ipv4 address should be unique for each host and you can just pick it up randomly,but using private address is recommended.  
My program does not check whether the IP address is legal or not,so just keep it correct.  
  
关于 v4v6map.txt:  
假设2001:xxxx::1是服务器IP，2001:xxxx::2-4是客户端IP  
服务器的v4v6map.txt:  
172.16.0.2  2001:xxxx::2  
172.16.0.3  2001:xxxx::3  
172.16.0.4  2001:xxxx::4  
  
客户端的v4v6map.txt:  
172.16.0.1  2001:xxxx::1  
  
其中的ipv4地址对于每个ipv6地址都应该是唯一的，ipv4地址是多少并没有多大关系，你可以随意选择，但是推荐使用内网地址  
此工具没有检查IP地址的合法性，所以请保证你输入的IP地址是正确的  
  
  
About compilation:  
I use VS2015 to compile,I have not tried earlier version of VS but I think it is ok.   
Use Release mode,disable the security check(/GS-) and code optimization(/Od).  
Owing to the self protection of Left4dead2,the dll will be unloaded immediately after DllMain() is finished,so my program use a special method to pass parameters(the last 10 "memcpy" of Writehookfunctions() do this and if you want to know what are they doing,you need to disassemble the dll file and check).So,if a different compiler is used or the settings of compiler are wrong,it may causes memory access violation after you injected it and left4dead2.exe would crash.  
  
关于编译:  
我使用VS2015，更早的版本我没有试过但应该没什么问题  
使用Release模式，关闭安全检查(/GS-)和代码优化(/Od)  
由于求生之路2的自我保护机制，注入的dll会在执行完DllMain之后立即被卸载，所以我使用了一种特殊的方法来绕过。（Writehookfunctions函数的最后10个memcpy是用来传递参数的，如果你想了解它是如何传递的，你需要逆向dll文件并查看）。所以如果你使用了其他编译器或者编译参数设置错误，dll注入后会发生内存访问错误然后求生之路2将崩溃  