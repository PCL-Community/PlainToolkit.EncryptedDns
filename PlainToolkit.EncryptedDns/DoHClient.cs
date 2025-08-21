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
            if (value.StartsWith("http:")) throw new SecurityException("此地址的 URI 解决方案无效，解决方案必须为 HTTPS 协议");
            _address = value;
        }
    }

    private static QueryOptions Options { get; set; } = QueryOptions.Mixed;
    private static readonly HttpClient Client = new(Handler);

    private static async Task<HttpResponseMessage> SendRequest(byte[] dnsMessage)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, DoHAddress);
        request.Content = new ByteArrayContent(dnsMessage);
        request.Content.Headers.TryAddWithoutValidation("Content-Type","application/dns-message");
        request.Headers.TryAddWithoutValidation("Accept", "application/dns-message");
        return await Client.SendAsync(request);
    }
    public static async Task<DnsResolveResult> SendDnsQueryV4Async(string address)
    {
        if (Options == QueryOptions.IPv6Only)
            return new DnsResolveResult() { Status = DnsResolveStatus.InternalBlocked };
        var message = Utils.GetDnsMessage(address, IPAddressType.IPv4);
        using var response = await SendRequest(message);
        return Utils.ParseDnsMessage(message, await response.Content.ReadAsByteArrayAsync());
    }

    public static async Task<DnsResolveResult> SendDnsQueryV6Async(string address)
    {
        if (Options == QueryOptions.IPv4Only)
            return new DnsResolveResult() { Status = DnsResolveStatus.InternalBlocked };
        var message = Utils.GetDnsMessage(address, IPAddressType.IPv6);
        using var response = await SendRequest(message);
        return Utils.ParseDnsMessage(message, await response.Content.ReadAsByteArrayAsync());
    }

    public static async Task<(DnsResolveResult ipv4Query, DnsResolveResult ipv6Query)> SendDnsQueryAsync(string address)
    {
        var task = new List<Task<DnsResolveResult>>([SendDnsQueryV4Async(address), SendDnsQueryV6Async(address)]);
        await Task.WhenAll(task);
        return (task[0].Result, task[1].Result);
    }
}
