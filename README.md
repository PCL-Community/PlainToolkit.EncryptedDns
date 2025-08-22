# PlainToolkit.EncryptedDns

A simple DNS resolution library for DoT/DoH integration.

>[!WARNING]
>
> The current version of this library only supports querying A and AAAA records. For CNAME records, the Status value in the DnsResolveResult class will be CNameRedirect.

## Usage

I've provided a simple method for integration. You only need to set the ConnectCallback of SocketsHttpHandler like this:

```CSharp
ConnectCallback = async(context, cts) => await HttpConnectCallback.GetNetworkStream(context, cts)
```

The GetNetworkStreammethod will select the optimal IP address based on RFC 8305 (Happy Eyeballs) algorithm and establish a TCP connection.

For the usage of DoT and DoH queries in the library itself, please refer to: [Wiki](https://github.com/PCL-Community/PlainToolkit.EncryptedDns/wiki)
