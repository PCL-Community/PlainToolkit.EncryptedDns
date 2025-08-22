using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Threading.Tasks;

namespace PlainToolkit.EncryptedDns;

public static class DoTClient
{
    public static string? DoTAddress { get; set; }
    public static QueryOptions QueryOption { get; set; } = QueryOptions.Mixed;

    private static uint _doTPort = 853;
    public static uint DoTPort
    {
        get => _doTPort;
        set
        {
            if (value > 65535)
                throw new FormatException("无效的端口号");
            _doTPort = value;
        }
    }

    // 辅助方法：异步精确读取
    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, int length,CancellationToken token)
    {
        var read = 0;
        while (read < length)
        {
            var n = await stream.ReadAsync(buffer,token);
            if (n == 0)
                throw new EndOfStreamException();
            read += n;
        }
    }

    public static async Task<DnsResolveResult> SendDnsQueryV6Async(string address,CancellationToken token)
    {
        try
        {
            if (QueryOption == QueryOptions.IPv4Only)
                return new DnsResolveResult { Status = DnsResolveStatus.InternalBlocked };

            return await SendRequestAsync(address, IPAddressType.IPv6, token);
        }
        catch (TaskCanceledException)
        {
            return new DnsResolveResult()
            {
                Status = DnsResolveStatus.Timeout
            };
        }
    }

    public static async Task<DnsResolveResult> SendDnsQueryV4Async(string address, CancellationToken token)
    {
        try
        {
            if (QueryOption == QueryOptions.IPv6Only)
                return new DnsResolveResult { Status = DnsResolveStatus.InternalBlocked };

            return await SendRequestAsync(address, IPAddressType.IPv4, token);
        }
        catch (TaskCanceledException)
        {
            return new DnsResolveResult()
            {
                Status = DnsResolveStatus.Timeout
            };
        }
    }

    private static async Task<DnsResolveResult> SendRequestAsync(string address, IPAddressType type,CancellationToken token)
    {
        if (string.IsNullOrEmpty(DoTAddress))
            throw new InvalidOperationException("DoTAddress 未设置");

        using var socket = new Socket(IPAddress.Parse(DoTAddress).AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(DoTAddress),(int)DoTPort),token);
        await using var networkStream = new NetworkStream(socket, ownsSocket: true);
        await using var sslStream = new SslStream(networkStream, false);

        await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = DoTAddress
        },token);

        var dnsMessage = Utils.GetDnsMessage(address, type);
        var lenBytes = BitConverter.GetBytes((ushort)dnsMessage.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes); // DNS over TLS 2字节长度为大端序

        await sslStream.WriteAsync(lenBytes, 0, lenBytes.Length,token);
        await sslStream.WriteAsync(dnsMessage, 0, dnsMessage.Length,token);

        var lengthBuf = new byte[2];
        await ReadExactlyAsync(sslStream, lengthBuf, 2,token);
        if (BitConverter.IsLittleEndian) Array.Reverse(lengthBuf);
        var respLen = BitConverter.ToUInt16(lengthBuf, 0);

        var respBuf = new byte[respLen];
        await ReadExactlyAsync(sslStream, respBuf, respLen,token);

        return Utils.ParseDnsMessage(dnsMessage, respBuf);
    }

    public static async Task<(DnsResolveResult ipv4Query, DnsResolveResult ipv6Query)> SendDnsQueryAsync(string address,TimeSpan? timeout = null)
    {
        using var token = new CancellationTokenSource(timeout ??= TimeSpan.FromMilliseconds(1000));
        var v4Task = SendDnsQueryV4Async(address,token.Token);
        var v6Task = SendDnsQueryV6Async(address,token.Token);
        await Task.WhenAny(v4Task, v6Task);
        token.CancelAfter(50);
        return (v4Task.Result, v6Task.Result);
    }
}