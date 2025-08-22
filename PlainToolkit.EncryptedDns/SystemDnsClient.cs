using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace PlainToolkit.EncryptedDns;

public static class SystemDnsClient
{
    // 保留原始签名
    public static QueryOptions Options { get; set; } = QueryOptions.Mixed;

    // 保留原始签名；并行执行 IPv4/IPv6 查询，共用同一个超时 token
    public static async Task<(DnsResolveResult ipv4Query, DnsResolveResult ipv6Query)> SendDnsQuery(string address, TimeSpan? timeout = null)
    {
        using var cts = new CancellationTokenSource(timeout ?? TimeSpan.FromMilliseconds(300));
        var v4Task = SendDnsQueryV4(address, cts.Token);
        var v6Task = SendDnsQueryV6(address, cts.Token);

        await Task.WhenAll(v4Task, v6Task).ConfigureAwait(false);

        return (await v4Task.ConfigureAwait(false), await v6Task.ConfigureAwait(false));
    }

    // 保留签名；改进实现细节
    public static async Task<DnsResolveResult> SendDnsQueryV4(string address, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(address))
            throw new ArgumentException("address cannot be null or empty.", nameof(address));

        try
        {
            var result = new DnsResolveResult()
            {
                AddressList = new List<NetAddress>()
            };

            // 如果只允许 IPv6，则 IPv4 查询被内部阻止
            if (Options == QueryOptions.IPv6Only)
            {
                result.Status = DnsResolveStatus.InternalBlocked;
                return result;
            }

            token.ThrowIfCancellationRequested();

            var addresses = await SendRequestAsync(address, token).ConfigureAwait(false);
            foreach (var ip in addresses)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    result.AddressList.Add(new NetAddress()
                    {
                        Address = ip,
                        ExpiredAt = DateTime.UtcNow.AddMinutes(10),
                        Type = IPAddressType.IPv4
                    });
                }
            }

            return result;
        }
        catch (TaskCanceledException)
        {
            return new DnsResolveResult()
            {
                Status = DnsResolveStatus.Timeout
            };
        }
    }

    // 保留签名；改进实现细节
    public static async Task<DnsResolveResult> SendDnsQueryV6(string address, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(address))
            throw new ArgumentException("address cannot be null or empty.", nameof(address));

        try
        {
            var result = new DnsResolveResult()
            {
                AddressList = new List<NetAddress>()
            };

            // 如果只允许 IPv4，则 IPv6 查询被内部阻止
            if (Options == QueryOptions.IPv4Only)
            {
                result.Status = DnsResolveStatus.InternalBlocked;
                return result;
            }

            token.ThrowIfCancellationRequested();

            var addresses = await SendRequestAsync(address, token).ConfigureAwait(false);
            foreach (var ip in addresses)
            {
                if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    result.AddressList.Add(new NetAddress()
                    {
                        Address = ip,
                        ExpiredAt = DateTime.UtcNow.AddMinutes(10),
                        Type = IPAddressType.IPv6
                    });
                }
            }

            return result;
        }
        catch (TaskCanceledException)
        {
            return new DnsResolveResult()
            {
                Status = DnsResolveStatus.Timeout
            };
        }
    }

    // 保留签名；简单封装系统 DNS 调用
    private static async Task<IPAddress[]> SendRequestAsync(string address, CancellationToken token)
    {
        return await Dns.GetHostAddressesAsync(address, token).ConfigureAwait(false);
    }
}