from scapy.all import Ether, IP, TCP, UDP, Raw, sendp, conf
import argparse
import sys

def send_packet(iface, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, 
                protocol, payload, count=1, verbose=True):
    """
    构造并发送自定义数据包
    
    参数:
        iface: 网络接口名称 (如 eth0, ens33) 这个可以使用命令 ip addr 查看
        src_mac: 源MAC地址
        dst_mac: 目标MAC地址
        src_ip: 源IP地址
        dst_ip: 目标IP地址
        src_port: 源端口
        dst_port: 目标端口
        protocol: 协议类型 (tcp/udp)
        payload: 数据负载
        count: 发送数据包数量
        verbose: 是否显示详细信息
    """
    """
    运行程序时使用下面参考命令(也可以自己发给自己,将发送接收mac都设置自己,ip都是127.0.0.1,端口随意)
    记得抓包时构造的数据包使用的是哪个网络接口就抓哪个接口的数据包,不然即使发送了也显示不出来
    (案例1关于src-mac和dst-mac那里是使用的自动获取的命令 但是如果知道发送方mac和接收方mac的话 可以使用案例2)
        案例1(我这里测试的时候iface是ens33,我的接收方是192.168.232.144,请根据实际情况修改):
        有可能存在我发送方是192.168.232.141,接收方是192.168.232.144,但是我作为发送方一开始的mac表里面还没有192.168.232.144的mac地址,
        所以在发送之前需要先ping一下接收方IP地址以确保mac地址已经在本地的邻居表里面了,否则会发送失败
        sudo python3 testcode.py \
          -i ens33 \
          --src-mac $(ip link show ens33 | grep -oP '(?<=link/ether )\S+') \
          --dst-mac $(ip neigh show 192.168.232.144 | grep -oP '(?<=lladdr )\S+') \
          --src-ip 192.168.232.141 \
          --dst-ip 192.168.232.144 \
          --src-port 12345 \
          --dst-port 8888 \
          --protocol udp \
          --payload "Hello from VM 141!" \
          --count 10
        案例2:
        sudo python3 testcode.py \
          -i ens33 \
          --src-mac 00:0c:29:3e:5b:7a \
          --dst-mac 00:0c:29:12:34:56 \
          --src-ip 192.168.232.141 \
          --dst-ip 192.168.232.144 \
          --src-port 12345 \
          --dst-port 8888 \
          --protocol udp \
          --payload "Hello from VM 141!" \
          --count 10
    """
    try:
        # 构造以太网层
        eth_layer = Ether(src=src_mac, dst=dst_mac)
        
        # 构造IP层
        ip_layer = IP(src=src_ip, dst=dst_ip)
        
        # 构造传输层
        if protocol.lower() == 'tcp':
            transport_layer = TCP(sport=src_port, dport=dst_port)
        elif protocol.lower() == 'udp':
            transport_layer = UDP(sport=src_port, dport=dst_port)
        else:
            print(f"错误: 不支持的协议 '{protocol}'")
            return False
        
        # 构造数据负载
        payload_layer = Raw(load=payload.encode() if isinstance(payload, str) else payload)
        
        # 组合所有层
        packet = eth_layer / ip_layer / transport_layer / payload_layer
        
        # verbose模式下显示数据包信息,这里就是这个参数的作用
        if verbose:
            print("\n" + "="*60)
            print("数据包信息:")
            print("="*60)
            packet.show()
            print("="*60)
            print(f"\n准备发送 {count} 个数据包到接口 {iface}...\n")
        
        # 发送数据包
        sendp(packet, iface=iface, count=count, verbose=verbose)
        
        print(f"\n成功发送 {count} 个数据包!")
        return True
        
    except Exception as e:
        print(f"发送数据包时出错: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='网络数据包发送测试工具 (需要root权限)'
    )
    
    parser.add_argument('-i', '--interface', required=True,
                        help='网络接口 (如 eth0, ens33)')
    parser.add_argument('--src-mac', required=True,
                        help='源MAC地址 (如 00:11:22:33:44:55)')
    parser.add_argument('--dst-mac', required=True,
                        help='目标MAC地址 (如 66:77:88:99:aa:bb)')
    parser.add_argument('--src-ip', required=True,
                        help='源IP地址 (如 192.168.1.100)')
    parser.add_argument('--dst-ip', required=True,
                        help='目标IP地址 (如 192.168.1.200)')
    parser.add_argument('--src-port', type=int, required=True,
                        help='源端口 (1-65535)')
    parser.add_argument('--dst-port', type=int, required=True,
                        help='目标端口 (1-65535)')
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp',
                        help='传输层协议 (默认: tcp)')
    parser.add_argument('--payload', default='Test Data',
                        help='数据负载内容 (默认: "Test Data")')
    parser.add_argument('-c', '--count', type=int, default=1,
                        help='发送数据包数量 (默认: 1)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='静默模式,不显示详细信息')
    
    args = parser.parse_args()
    
    # 检查是否以root权限运行
    if sys.platform.startswith('linux'):
        import os
        if os.geteuid() != 0:
            print("错误: 此程序需要root权限运行!")
            print("请使用: sudo python3", sys.argv[0])
            sys.exit(1)
    
    # 禁用Scapy的警告信息
    conf.verb = 0 if args.quiet else 1
    
    # 验证端口范围
    if not (1 <= args.src_port <= 65535):
        print("错误: 源端口必须在 1-65535 之间")
        sys.exit(1)
    if not (1 <= args.dst_port <= 65535):
        print("错误: 目标端口必须在 1-65535 之间")
        sys.exit(1)
    
    # 发送数据包
    success = send_packet(
        iface=args.interface,
        src_mac=args.src_mac,
        dst_mac=args.dst_mac,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        protocol=args.protocol,
        payload=args.payload,
        count=args.count,
        verbose=not args.quiet
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
