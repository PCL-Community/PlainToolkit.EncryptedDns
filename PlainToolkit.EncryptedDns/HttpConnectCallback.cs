using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace PlainToolkit.EncryptedDns;

public static class HttpConnectCallback
{
    private class AddressInfo
    {
        public required DnsResolveResult ResolveResult { get; set; }
        public required int Port { get; set; }
    }
    
    private static ConcurrentDictionary<string, NetAddress> _queryCache = new();
    private static TimeSpan Timeout { get; set; } = TimeSpan.FromMilliseconds(300);
    public static DnsQueryIssuer QueryIssuer { get; set; } = DnsQueryIssuer.System;
    /// <summary>
    /// 获取目标主机的网络流（基于 RFC 8305 选址算法）
    /// </summary>
    /// <param name="context"></param>
    /// <param name="token"></param>
    /// <returns></returns>
    public static async Task<NetworkStream> GetNetworkStream(SocketsHttpConnectionContext context,
        CancellationToken token)
    {
        // 降低 DNS 查询开销
        if (_queryCache.TryGetValue(context.DnsEndPoint.Host, out var cache))
        {
            if (cache.ExpiredAt > DateTime.Now)
            {
                var socket = new Socket(cache.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(new IPEndPoint(cache.Address, context.DnsEndPoint.Port), token);
                return new NetworkStream(socket, true);
            }
            else _queryCache.TryRemove(KeyValuePair.Create(context.DnsEndPoint.Host, cache));
        }
        
        var resolveResult = QueryIssuer switch
        {
            DnsQueryIssuer.DoT => await DoTClient.SendDnsQueryAsync(context.DnsEndPoint.Host, Timeout),
            DnsQueryIssuer.DoH => await DoHClient.SendDnsQueryAsync(context.DnsEndPoint.Host, Timeout),
            _ => await SystemDnsClient.SendDnsQuery(context.DnsEndPoint.Host)
        };
        // Failed/CNAME Redirect 的情况下应当传递 null
        // 这可以让 StartConnect 知道这个域名在 IPv4/6 下没有解析记录，从而减少 RFC 8305 选址算法带来的额外开销
        var addrInfoV6 = resolveResult.ipv6Query.Status switch
        {
            DnsResolveStatus.Success => new AddressInfo()
            {
                ResolveResult = resolveResult.ipv6Query,
                Port = context.DnsEndPoint.Port
            },
            _ => null
        };
        var addrInfoV4 = resolveResult.ipv4Query.Status switch
        {
            DnsResolveStatus.Success => new AddressInfo()
            {
                ResolveResult = resolveResult.ipv4Query,
                Port = context.DnsEndPoint.Port
            },
            _ => null
        };
        var socketResult = await StartConnect(context.DnsEndPoint.Host,addrInfoV6, addrInfoV4, token);
        
        return new NetworkStream(socketResult ?? throw new SocketException(11001,$"未能解析此远程地址：{context.DnsEndPoint.Host}"), true);
    }
    /// <summary>
    /// 基于 RFC 8305 选址算法获取对应域名的 IPv6/4 链路连接
    /// </summary>
    /// <param name="hostName">主机域名</param>
    /// <param name="ipv6">AddressInfo IPv6 链路连接信息</param>
    /// <param name="ipv4">AddressInfo IPv4 链路连接信息</param>
    /// <param name="token">用于中断连接任务的取消令牌</param>
    /// <returns>该域名的 IPv6/4 链路连接（Socket 套接字）</returns>
    private static async Task<Socket?> StartConnect(string hostName,AddressInfo? ipv6,AddressInfo? ipv4,CancellationToken token)
    {
        var taskList = new List<Task<Task<(Socket? socket, NetAddress? addr)>>>();
        var socketV6 = Task.WhenAny(StartIPv6Connect(ipv6, token));
        // Ref: RFC 8305，延迟 40 ms 启动 IPv4 连接
        if (Socket.OSSupportsIPv6 && ipv6 is not null) await Task.Delay(40,token);
        // IPv6 对于数据传输优化更好，在已经建立 IPv6 链路连接的情况下可直接返回 IPv6 链路连接
        if (socketV6.GetAwaiter().IsCompleted)
        {
            if (socketV6.Result.Result.socket is not null)
            {
                _queryCache.TryAdd(hostName, socketV6.Result.Result.addr!);
                return socketV6.Result.Result.socket;
            }
        }

        if (ipv4 is not null)
        {
            var socketV4 = Task.WhenAny([StartIPv4Connect(ipv4, token)]);
            taskList.Add(socketV4);
        }
        taskList.Add(socketV6);
        var result = await Task.WhenAny(taskList);
        if (result.Result.Result.socket is not null)
        {
            _queryCache.TryAdd(hostName, result.Result.Result.addr!);
        }
        return null;
    }
    private static async Task<(Socket? socket,NetAddress? addr)> StartIPv6Connect(AddressInfo? address,CancellationToken token)
    {
        if (address is null) return (null,null);
        var taskList = new List<Task<(Socket socket,NetAddress addr)>>();
        foreach (var addr in address.ResolveResult.AddressList ?? [])
        {
            taskList.Add(Task.Run(async () =>
            {
                var watcher = Stopwatch.StartNew();
                var socket = new Socket(addr.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(new IPEndPoint(addr.Address, address.Port), token);
                watcher.Stop();
                return (socket,addr);
            },token));
        }

        return (await Task.WhenAny(taskList)).Result;
    }
    private static async Task<(Socket? socket,NetAddress? addr)> StartIPv4Connect(AddressInfo? address,CancellationToken token)
    {
        if (address is null) return (null,null);
        var taskList = new List<Task<(Socket socket,NetAddress addr)>>();
        foreach (var addr in address.ResolveResult.AddressList!)
        {
            taskList.Add(Task.Run(async () =>
            {
                var socket = new Socket(addr.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(new IPEndPoint(addr.Address, address.Port), token);
                return (socket,addr);
            },token));
        }
        return (await Task.WhenAny(taskList)).Result;
    }

}


public enum DnsQueryIssuer
{
    DoH,
    DoT,
    System
}
