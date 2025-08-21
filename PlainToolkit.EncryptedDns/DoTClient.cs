using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Threading.Tasks;

namespace PlainToolkit.EncryptedDns;

public static class DoTClient
{
    public static string? DoTAddress { get; set; }
    public static QueryOptions QueryOption { get; set; } = QueryOptions.Mixed;

    private static int _doTPort = 853;
    public static int DoTPort
    {
        get => _doTPort;
        set
        {
            if (value is <= 0 or > 65535)
                throw new FormatException("无效的端口号");
            _doTPort = value;
        }
    }

    // 辅助方法：异步精确读取
    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, int length)
    {
        int read = 0;
        while (read < length)
        {
            int n = await stream.ReadAsync(buffer, read, length - read);
            if (n == 0)
                throw new EndOfStreamException();
            read += n;
        }
    }

    public static async Task<DnsResolveResult> SendDnsQueryV6Async(string address)
    {
        if (QueryOption == QueryOptions.IPv4Only)
            return new DnsResolveResult { Status = DnsResolveStatus.InternalBlocked };

        return await SendDnsQueryAsync(address, IPAddressType.IPv6);
    }

    public static async Task<DnsResolveResult> SendDnsQueryV4Async(string address)
    {
        if (QueryOption == QueryOptions.IPv6Only)
            return new DnsResolveResult { Status = DnsResolveStatus.InternalBlocked };

        return await SendDnsQueryAsync(address, IPAddressType.IPv4);
    }

    private static async Task<DnsResolveResult> SendDnsQueryAsync(string address, IPAddressType type)
    {
        if (string.IsNullOrEmpty(DoTAddress))
            throw new InvalidOperationException("DoTAddress 未设置");

        using var socket = new Socket(IPAddress.Parse(DoTAddress).AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(DoTAddress, DoTPort);
        using var networkStream = new NetworkStream(socket, ownsSocket: true);
        using var sslStream = new SslStream(networkStream, false);

        await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = DoTAddress
        });

        var dnsMessage = Utils.GetDnsMessage(address, type);
        var lenBytes = BitConverter.GetBytes((ushort)dnsMessage.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes); // DNS over TLS 2字节长度为大端序

        await sslStream.WriteAsync(lenBytes, 0, lenBytes.Length);
        await sslStream.WriteAsync(dnsMessage, 0, dnsMessage.Length);

        var lengthBuf = new byte[2];
        await ReadExactlyAsync(sslStream, lengthBuf, 2);
        if (BitConverter.IsLittleEndian) Array.Reverse(lengthBuf);
        ushort respLen = BitConverter.ToUInt16(lengthBuf, 0);

        var respBuf = new byte[respLen];
        await ReadExactlyAsync(sslStream, respBuf, respLen);

        return Utils.ParseDnsMessage(dnsMessage, respBuf);
    }

    public static async Task<(DnsResolveResult ipv4Query, DnsResolveResult ipv6Query)> SendDnsQueryAsync(string address)
    {
        // 并发查询，无需静态锁
        var v4Task = SendDnsQueryV4Async(address);
        var v6Task = SendDnsQueryV6Async(address);
        await Task.WhenAll(v4Task, v6Task);
        return (v4Task.Result, v6Task.Result);
    }
}