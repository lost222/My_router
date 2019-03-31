# My_router
# 网络技术应用   路由器文档

**1610299**

**杨起**

[TOC]

##  程序架构

主进程有两个线程, 每个线程是一个网卡的抽象, 监听一个网卡, 保存自己的路由表

`Mythread` 监听一个显卡,

每监听到一个数据,  判断该不该传送给主进程处理:

  - 我的路由表里查得到的不传送(这个不应该转发)
  - MAC地址不是我的不转发
  - ARP信息自己处理自己的, 不交给主进程

主进程收到数据报, 分别查询两个线程各自维护的路由表,  在哪里查到就用谁转发



## 网卡抽象---MyThread 类

这是一个**线程**, 监听一个固定的网卡(这张网卡上有**一个**IP地址).对接到的信息做一些处理. 

每一个网卡都有自己的`arp_table`和`route_table`, 含义是, 如果一个报文从网卡A转发出去, 那么A应该就有

1. 对于该报文的合适的路由表

2. 关于报文目的地址的(或者下一跳地址的) `arp` 信息

说的再详细一点, 这个时候, 另一个网卡B是完全没有关于这个报文该怎么转发的信息的.(B的路由表里不包含能够转发该报文的信息)

### 路由表数据结构

`route_table`是简单的`vector` , 为了最基础的转发能够成功,保存情况如下

保存空间复杂度o(n) 

网卡A的路由表

| NETIP     | MASK        | NEXT JUMP |
| --------- | ----------- | --------- |
| 206.1.2.0 | 255.255.255 | 206.1.2.0 |
| 206.1.3.0 | 255.255.255 | 206.1.2.2 |

网卡B的路由表

| NETIP     | MASK        | NEXT JUMP |
| --------- | ----------- | --------- |
| 206.1.1.0 | 255.255.255 | 206.1.1.0 |

#### 直接转发的保存方式

对于需要直接转发的路由记录, 保存的**NEXT JUMP**和**NETIP**相等,  这是一个简单trick,好处在于可以统一保存的形式为`Vector<unsigned int>` . 而且不占用某个特殊IP地址,也不会有什么差错.这个见后面完整转发流程的时候会详细分析.



### 查表方法

简单扫一遍, O(n) 级别算法. 支持最长路由 ( 即对于有多条路由记录满足要求的情况下, 取MASK最大的)


~~~c++
int MyThread::check_route_table(unsigned int ip)
{

    QVector<unsigned int> results;
    // 扫一遍, 所有可以转发数据报的路由记录都加入results
    for(int i=0; i<route_table.size();i++) {
        unsigned int netId = ip&route_table[i].at(1);
        if (netId == route_table[i].at(0)) {
            results.append(i);
        }
    }
    // 如果一条也没有返回零
    if (results.size() == 0) {
        return -1;
    }
    // 在results里找MASK最大的
    int realResult = results.at(0);
    for(int i=0; i<results.size(); i++) {
        int row = results.at(i);
        if ( route_table.at(realResult).at(1) < route_table.at(row).at(1) ) {
            realResult = row ;
        }
    }
    // 返回的是路由记录在路由表里的顺序
    return realResult;
}
~~~



### ARP方法

每当网卡接到消息的时候,先判断是不是`ARP`消息, 如果是的话, 网卡自己处理,处理流程和之前和一样, 提取IP-->MAC信息, 保存在网卡自己的ARP表里就行.



## 完整的转发流程例子

![routeShow](https://github.com/lost222/My_FTP/tree/master/image/route_show.png)

1. 路由程序启动,两个`Thread`类对象init, 拿到自己监听的IP(利用`WinpCap`) 发送伪ARP报文, 获得自己的MAC地址.线程start
2. 某个网卡接到报文, 判断应不应该转发给主进程

~~~C++
// 线程run方法里监听循环的一部分
if (Frame_type_real == 0x0806) { 
    // 保存进自己的arp表
    deal_with_arp_datagram(IPPacket);
} else if (Frame_type_real == 0x0800) { 
    // 交给主进程处理 
    // 我们现在只转发IPV4报文
    deal_with_other_datagram((Data_t*)pkt_data);
}
~~~

3. 假设是应该转发的报文, 进入`deal_with_other_datagram`继续判断一下目的MAC是不是自己, 如果是, 转发给主进程.
4. 主进程收到报文, 判断一下是不是发给自己的, 如果是, 不转发. 如果不是,开始转发流程

~~~C++
    // 主进程查表
    int where = thread.check_route_table(to_ip);
    // 在不在thread对象的路由表里
	if ( where > -1 ) {
        
        //是否直接投递
        if(thread.route_table[where].at(0) == thread.route_table[where].at(2) ) {
			// 直接投递 
            send_data_use_ip(to_ip, datagram, len, 1);
        } else {
            // 不是直接投递 转发到下一跳的位置
            send_data_use_ip(thread.route_table[where].at(2), datagram, len, 1);
        }
    }
	// 对于网卡2同样做一遍
    int where2 = adapter2.check_route_table(to_ip);
    if ( where2 > -1) {

        if(adapter2.route_table[where2].at(0) == adapter2.route_table[where2].at(2) ) {
            send_data_use_ip(to_ip, datagram, len, 2);
        } else {
            // 不是直接投递
            send_data_use_ip(adapter2.route_table[where2].at(2), datagram, len, 2);
        }
    }

~~~

5. `send_data_use_ip`函数会改换数据报的`SrcMAC`和`DesMAC` , 发送到由IP地址指定的机子上去. 中间有获取目的机子的MAC地址过程,上一次做过就不详细说了



一些细节:

* 线程和进程中传输的是数据报的指针, 数据报并没有被多次复制
* 转发实际上调用的是主进程的函数, 这个函数也可以实现在线程里.





## 路由表管理

允许使用如下语法进行路由表管理

### 添加

~~~shell
add 206.1.3.0  255.255.255.0  206.2.2.2
~~~

### 删除

~~~she
del 206.1.3.0  255.255.255.0  206.2.2.2
~~~

添加和删除的时候会判断语法和语义上的错误, 如果出错了的话不予理会

错误例子

* 语句语法不全
* 添加的路由记录下一条不在当前路由表可以直接送达的范围内



## 程序界面

![](https://github.com/lost222/My_FTP/tree/master/image/router_inter.png)

可以通过在对话框里输入指令之后点击`ACTION`完成路由表管理
