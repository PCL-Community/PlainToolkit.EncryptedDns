using System.Net;
using System.Net.Sockets;

namespace PlainToolkit.EncryptedDns;

public static class SystemDnsClient
{
    public static QueryOptions Options { get; set; } = QueryOptions.Mixed;
    public static async Task<(DnsResolveResult ipv4Query, DnsResolveResult ipv6Query)> SendDnsQuery(string address,TimeSpan? timeout = null)
    {
        using var token = new CancellationTokenSource(timeout ?? TimeSpan.FromMilliseconds(300));
        return (await SendDnsQueryV6(address, token.Token),await SendDnsQueryV6(address, token.Token));
    }

    public static async Task<DnsResolveResult> SendDnsQueryV4(string address, CancellationToken token)
    {
        try
        {
            var result = new DnsResolveResult()
            {
                AddressList = []
            };
            if (Options == QueryOptions.IPv4Only)
            {
                result.Status = DnsResolveStatus.InternalBlocked;
                return result;
            }

            _ = (await SendRequestAsync(address, token)).Any(_address =>
            {
                if (_address.AddressFamily == AddressFamily.InterNetwork)
                {
                    result.AddressList.Add(new NetAddress()
                    {
                        Address = _address,
                        ExpiredAt = DateTime.Now.AddMinutes(10),
                        Type = IPAddressType.IPv4
                    });
                }

                return false;
            });
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

    public static async Task<DnsResolveResult> SendDnsQueryV6(string address, CancellationToken token)
    {
        try
        {
            var result = new DnsResolveResult()
            {
                AddressList = []
            };
            if (Options == QueryOptions.IPv4Only)
            {
                result.Status = DnsResolveStatus.InternalBlocked;
                return result;
            }

            _ = (await SendRequestAsync(address, token)).Any(_address =>
            {
                if (_address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    result.AddressList.Add(new NetAddress()
                    {
                        Address = _address,
                        ExpiredAt = DateTime.Now.AddMinutes(10),
                        Type = IPAddressType.IPv6
                    });
                }

                return false;
            });
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

    private static async Task<IPAddress[]> SendRequestAsync(string address, CancellationToken token)
    {
        return await Dns.GetHostAddressesAsync(address, token);
    }
}