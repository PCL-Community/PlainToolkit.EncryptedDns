using System.Security;

namespace PlainToolkit.EncryptedDns;

public static class DoHClient
{
    private static readonly SocketsHttpHandler Handler = new()
    {
        UseProxy = true,
        Proxy = HttpProxy.Instance
    };

    private static string? _address;
    public static string DoHAddress
    {
        get => _address ?? throw new ArgumentNullException(nameof(_address),"未设置 DoH 地址");
        set
        {
            if (value.TrimEnd().Length == 0) throw new FormatException("此 URI 为空字符串");
            if (!value.StartsWith("https:")) throw new SecurityException("此地址的 URI 解决方案无效，解决方案必须为 HTTPS 协议");
            _address = value;
        }
    }

    private static QueryOptions Options { get; set; } = QueryOptions.Mixed;
    private static readonly HttpClient Client = new(Handler);

    private static async Task<HttpResponseMessage> SendRequest(byte[] dnsMessage,CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, DoHAddress);
        request.Content = new ByteArrayContent(dnsMessage);
        request.Content.Headers.TryAddWithoutValidation("Content-Type","application/dns-message");
        request.Headers.TryAddWithoutValidation("Accept", "application/dns-message");
        return await Client.SendAsync(request,token);
    }
    public static async Task<DnsResolveResult> SendDnsQueryV4Async(string address,CancellationToken token)
    {
        try
        {
            if (Options == QueryOptions.IPv6Only)
                return new DnsResolveResult() { Status = DnsResolveStatus.InternalBlocked };
            var message = Utils.GetDnsMessage(address, IPAddressType.IPv4);
            using var response = await SendRequest(message, token);
            return Utils.ParseDnsMessage(message, await response.Content.ReadAsByteArrayAsync(token));
        }
        catch (TaskCanceledException)
        {
            return new DnsResolveResult()
            {
                Status = DnsResolveStatus.Timeout
            };
        }
    }

    public static async Task<DnsResolveResult> SendDnsQueryV6Async(string address,CancellationToken token)
    {
        try
        {
            if (Options == QueryOptions.IPv4Only)
                return new DnsResolveResult() { Status = DnsResolveStatus.InternalBlocked };
            var message = Utils.GetDnsMessage(address, IPAddressType.IPv6);
            using var response = await SendRequest(message, token);
            return Utils.ParseDnsMessage(message, await response.Content.ReadAsByteArrayAsync(token));
        }
        catch (TaskCanceledException)
        {
            return new DnsResolveResult()
            {
                Status = DnsResolveStatus.Timeout
            };
        }
    }

    public static async Task<(DnsResolveResult ipv4Query, DnsResolveResult ipv6Query)> SendDnsQueryAsync(string address,TimeSpan? timeout = null)
    {
        using var token = new CancellationTokenSource(timeout??TimeSpan.FromMilliseconds(300));
        var queryV4 = SendDnsQueryV4Async(address, token.Token);
        var queryV6 = SendDnsQueryV6Async(address, token.Token);
        var task = new List<Task<DnsResolveResult>>([queryV4,queryV6]);
        await Task.WhenAny(task);
        // 给与剩余查询任务 50 ms 的时间
        token.CancelAfter(50);
        await Task.WhenAll(task);
        return (task[0].Result, task[1].Result);
    }
}
