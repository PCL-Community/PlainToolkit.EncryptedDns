using System.Net;

namespace PlainToolkit.EncryptedDns;

public class HttpProxy:IWebProxy
{
    public static readonly HttpProxy Instance = new();
    public bool EnableProxy { get; set; } = true;
    public IWebProxy Proxy { get; set; } = HttpClient.DefaultProxy;
    public Uri GetProxy(Uri destination) => new(Proxy.GetProxy(destination)?.AbsoluteUri ?? destination.ToString());
    public bool IsBypassed(Uri host) => !EnableProxy || Proxy.IsBypassed(host);
    public ICredentials? Credentials { get; set; }
}