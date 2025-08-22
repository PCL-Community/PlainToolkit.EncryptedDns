using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace PlainToolkit.EncryptedDns;

public static class HttpConnectCallback
{
    private class AddressInfo
    {
        public required DnsResolveResult ResolveResult { get; set; }
        public required int Port { get; set; }
    }

    private static readonly ConcurrentDictionary<string, NetAddress> QueryCache = new();
    private static TimeSpan Timeout { get; set; } = TimeSpan.FromMilliseconds(300);
    public static DnsQueryIssuer QueryIssuer { get; set; } = DnsQueryIssuer.System;

    /// <summary>
    /// 获取目标主机的网络流（基于 RFC 8305 选址算法）
    /// 如果 host 是 IP 地址文本，则直接跳过 DNS 查询并直接连接该 IP。
    /// </summary>
    public static async Task<NetworkStream> GetNetworkStream(SocketsHttpConnectionContext context,
        CancellationToken token)
    {
        if (context is null) throw new ArgumentNullException(nameof(context));
        var host = context.DnsEndPoint.Host;

        // 处理可能的 IPv6 中括号表示（如 [::1]）或其它包裹
        var hostTrimmed = host.Trim().TrimStart('[').TrimEnd(']');

        // 尝试作为字面 IP 直接连接（跳过 DNS）
        if (IPAddress.TryParse(hostTrimmed, out var literalIp))
        {
            // 检查缓存：若有有效缓存且未过期，优先使用缓存地址（缓存 key 使用原始 host 字符串以兼容以前逻辑）
            if (QueryCache.TryGetValue(host, out var cached) && cached.ExpiredAt > DateTime.UtcNow)
            {
                var cachedSocket = new Socket(cached.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await cachedSocket.ConnectAsync(new IPEndPoint(cached.Address, context.DnsEndPoint.Port), token).ConfigureAwait(false);
                return new NetworkStream(cachedSocket, ownsSocket: true);
            }

            // 直接对字面 IP 建立连接
            var socket = new Socket(literalIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(literalIp, context.DnsEndPoint.Port), token).ConfigureAwait(false);

            // 把地址加入缓存以便后续复用（与域名解析路径使用相同的 TTL）
            var netAddr = new NetAddress()
            {
                Address = literalIp,
                ExpiredAt = DateTime.UtcNow.AddMinutes(10),
                Type = literalIp.AddressFamily == AddressFamily.InterNetwork ? IPAddressType.IPv4 : IPAddressType.IPv6
            };
            QueryCache[host] = netAddr;

            return new NetworkStream(socket, ownsSocket: true);
        }

        // 先尝试缓存以降低 DNS 查询开销（域名路径）
        if (QueryCache.TryGetValue(host, out var cache))
        {
            if (cache.ExpiredAt > DateTime.UtcNow)
            {
                var cachedSocket = new Socket(cache.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await cachedSocket.ConnectAsync(new IPEndPoint(cache.Address, context.DnsEndPoint.Port), token).ConfigureAwait(false);
                return new NetworkStream(cachedSocket, ownsSocket: true);
            }
            else
            {
                QueryCache.TryRemove(host, out _);
            }
        }

        // 根据配置选择 DNS 查询器（为 System 保持兼容签名：SendDnsQuery 有超时重载）
        var resolveResult = QueryIssuer switch
        {
            DnsQueryIssuer.DoT => await DoTClient.SendDnsQueryAsync(host, Timeout).ConfigureAwait(false),
            DnsQueryIssuer.DoH => await DoHClient.SendDnsQueryAsync(host, Timeout).ConfigureAwait(false),
            _ => await SystemDnsClient.SendDnsQuery(host, Timeout).ConfigureAwait(false)
        };

        // 如果在对应协议下解析成功则创建 AddressInfo，否则为 null（以便 RFC 8305 算法识别没有记录的情况）
        var addrInfoV6 = resolveResult.ipv6Query.Status == DnsResolveStatus.Success
            ? new AddressInfo { ResolveResult = resolveResult.ipv6Query, Port = context.DnsEndPoint.Port }
            : null;

        var addrInfoV4 = resolveResult.ipv4Query.Status == DnsResolveStatus.Success
            ? new AddressInfo { ResolveResult = resolveResult.ipv4Query, Port = context.DnsEndPoint.Port }
            : null;

        var socketResult = await StartConnect(host, addrInfoV6, addrInfoV4, token).ConfigureAwait(false);

        if (socketResult is null)
        {
            // 保持原有行为：找不到地址时抛出 WSAHOST_NOT_FOUND
            throw new SocketException(11001);
        }

        return new NetworkStream(socketResult, ownsSocket: true);
    }

    /// <summary>
    /// 基于 RFC 8305 选址算法获取对应域名的 IPv6/4 链路连接
    /// </summary>
    private static async Task<Socket?> StartConnect(string hostName, AddressInfo? ipv6, AddressInfo? ipv4, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(hostName)) throw new ArgumentException("hostName cannot be null or empty.", nameof(hostName));
        if (ipv6 is null && ipv4 is null) return null;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        var linkedToken = linkedCts.Token;

        Task<(Socket? socket, NetAddress? addr)>? ipv6Task = ipv6 is not null ? StartIPv6Connect(ipv6, linkedToken) : null;

        if (Socket.OSSupportsIPv6 && ipv6 is not null)
        {
            try
            {
                await Task.Delay(40, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return null;
            }
        }

        var ipv4Task = ipv4 is not null ? StartIPv4Connect(ipv4, linkedToken) : Task.FromResult<(Socket? socket, NetAddress? addr)>((null, null));

        var candidates = new List<Task<(Socket? socket, NetAddress? addr)>>();
        if (ipv6Task is not null) candidates.Add(ipv6Task);
        if (ipv4Task is not null) candidates.Add(ipv4Task);

        while (candidates.Count > 0)
        {
            Task<(Socket? socket, NetAddress? addr)> finished;
            try
            {
                finished = await Task.WhenAny(candidates).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            candidates.Remove(finished);

            (Socket? socket, NetAddress? addr) result;
            try
            {
                result = await finished.ConfigureAwait(false);
            }
            catch
            {
                continue;
            }

            if (result.socket is not null)
            {
                if (result.addr is not null)
                {
                    QueryCache[hostName] = result.addr;
                }

                try { linkedCts.Cancel(); } catch { /* ignore */ }

                return result.socket;
            }
        }

        return null;
    }

    private static async Task<(Socket? socket, NetAddress? addr)> StartIPv6Connect(AddressInfo? address, CancellationToken token)
    {
        if (address is null || address.ResolveResult.AddressList is null || address.ResolveResult.AddressList.Count == 0)
            return (null, null);

        var connectTasks = new List<Task<(Socket? socket, NetAddress? addr)>>(capacity: address.ResolveResult.AddressList.Count);
        foreach (var addr in address.ResolveResult.AddressList)
        {
            connectTasks.Add(Task.Run(async () =>
            {
                Socket? socket = null;
                try
                {
                    var sw = Stopwatch.StartNew();
                    socket = new Socket(addr.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    await socket.ConnectAsync(new IPEndPoint(addr.Address, address.Port), token).ConfigureAwait(false);
                    sw.Stop();
                    return (socket, addr);
                }
                catch
                {
                    if (socket is not null)
                    {
                        try { socket.Dispose(); } catch { /* ignore */ }
                    }
                    return (null, null);
                }
            }, token));
        }

        while (connectTasks.Count > 0)
        {
            Task<(Socket? socket, NetAddress? addr)> completed;
            try
            {
                completed = await Task.WhenAny(connectTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            connectTasks.Remove(completed);

            try
            {
                var res = await completed.ConfigureAwait(false);
                if (res.socket is not null) return res;
            }
            catch
            {
                // 忽略单个连接任务的异常
            }
        }

        return (null, null);
    }

    private static async Task<(Socket? socket, NetAddress? addr)> StartIPv4Connect(AddressInfo? address, CancellationToken token)
    {
        if (address is null || address.ResolveResult.AddressList is null || address.ResolveResult.AddressList.Count == 0)
            return (null, null);

        var connectTasks = new List<Task<(Socket? socket, NetAddress? addr)>>(capacity: address.ResolveResult.AddressList.Count);
        foreach (var addr in address.ResolveResult.AddressList)
        {
            connectTasks.Add(Task.Run(async () =>
            {
                Socket? socket = null;
                try
                {
                    socket = new Socket(addr.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    await socket.ConnectAsync(new IPEndPoint(addr.Address, address.Port), token).ConfigureAwait(false);
                    return (socket, addr);
                }
                catch
                {
                    if (socket is not null)
                    {
                        try { socket.Dispose(); } catch { /* ignore */ }
                    }
                    return (null, null);
                }
            }, token));
        }

        while (connectTasks.Count > 0)
        {
            Task<(Socket? socket, NetAddress? addr)> completed;
            try
            {
                completed = await Task.WhenAny(connectTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            connectTasks.Remove(completed);

            try
            {
                var res = await completed.ConfigureAwait(false);
                if (res.socket is not null) return res;
            }
            catch
            {
                // 忽略单个连接任务的异常
            }
        }

        return (null, null);
    }
}

public enum DnsQueryIssuer
{
    DoH,
    DoT,
    System
}