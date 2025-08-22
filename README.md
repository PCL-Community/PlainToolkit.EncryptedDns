# PlainToolkit.EncryptedDns

A straightforward DNS resolution library for integration with DoT (DNS over TLS) and DoH (DNS over HTTPS).

> [!WARNING]
>
> The current version of this library only supports querying A and AAAA records. For CNAME records, the `Status` value in the `DnsResolveResult` class will be `CNameRedirect`.

## Usage Instructions

To facilitate integration, a simple method is provided. You just need to set the `ConnectCallback` of `SocketsHttpHandler` as follows:

```csharp
ConnectCallback = async (context, cts) => await HttpConnectCallback.GetNetworkStream(context, cts);
```

The `GetNetworkStream` method selects the optimal IP address based on the RFC 8305 (Happy Eyeballs) algorithm and establishes a TCP connection.

Next, configure the DoTClient.DoTAddress or DoHClient.DoHAddress according to whether you're using a DoT or DoH server.

By default, the DoTClient uses port 853 for establishing connections to DoT servers. If your DoT server operates on a different port, adjust the DoTClient.Port property accordingly.

For detailed instructions on how to perform DoT and DoH queries within the library itself, please refer to the [Wiki](https://github.com/PCL-Community/PlainToolkit.EncryptedDns/wiki).

## Feedback and Contributions

If you encounter any bugs or have suggestions for improvements, feel free to open an issue on our repository.

Contributions are welcome. If you have the skills and interest, we also welcome pull requests.

For security-related issues, please report them through the Security tab.

## License

This dependency library is open-sourced under the MIT License.
