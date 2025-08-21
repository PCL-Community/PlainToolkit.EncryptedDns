using PlainToolkit.EncryptedDns;
namespace PlainDnsClientTest;

public class Tests
{
    [Test]
    public void ParseDnsMessageTest()
    {
        var data = File.ReadAllBytes("response");
        var query = File.ReadAllBytes("dnsv4.bin");
        var result = Utils.ParseDnsMessage(query, data);
        foreach(var ip in result.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.TimeToLive);
            Console.WriteLine(ip.Type);
        }
    }
    [Test]
    public void MakeQuery()
    {
        File.WriteAllBytes("dns4.bin",Utils.GetDnsMessage("boximengling.luotianyi-0712.top",IPAddressType.IPv4));
        
        File.WriteAllBytes("dns6.bin",Utils.GetDnsMessage("boximengling.luotianyi-0712.top",IPAddressType.IPv6));
    }
    [Test]
    public void StartQueryTest()
    {
        
        DoTClient.DoTAddress = "223.5.5.5";
        var result = DoTClient.SendDnsQueryAsync("boximengling.luotianyi-0712.top").GetAwaiter().GetResult();
        Console.WriteLine(result.ipv4Query.Status);
        Console.WriteLine(result.ipv6Query.Status);
        Console.WriteLine(result.ipv4Query.AddressList?.Count ?? 0);
        Console.WriteLine(result.ipv6Query.AddressList?.Count ?? 0);
        Console.WriteLine(result.ipv4Query.CName);
        Console.WriteLine(result.ipv6Query.CName);
        foreach(var ip in result.ipv4Query.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.TimeToLive);
            Console.WriteLine(ip.Type);
        }
        foreach(var ip in result.ipv6Query.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.TimeToLive);
            Console.WriteLine(ip.Type);
        }
        
    }
    [Test]
    public void StartDoHQueryTest()
    {
        DoHClient.DoHAddress = "https://223.5.5.5/dns-query";
        var result = DoHClient.SendDnsQueryAsync("blog.tangge233.top").GetAwaiter().GetResult();
        Console.WriteLine(result.ipv4Query.Status);
        Console.WriteLine(result.ipv6Query.Status);
        Console.WriteLine(result.ipv4Query.AddressList?.Count ?? 0);
        Console.WriteLine(result.ipv6Query.AddressList?.Count ?? 0);
        Console.WriteLine(result.ipv4Query.CName);
        Console.WriteLine(result.ipv6Query.CName);
        foreach(var ip in result.ipv4Query.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.TimeToLive);
            Console.WriteLine(ip.Type);
        }
        foreach(var ip in result.ipv6Query.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.TimeToLive);
            Console.WriteLine(ip.Type);
        }
    }
}