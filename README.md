# Secure ModerHttpClient

Available on NuGet: https://www.nuget.org/packages/secure-modernhttpclient/ [![NuGet](https://img.shields.io/nuget/v/secure-modernhttpclient.svg?label=NuGet)](https://www.nuget.org/packages/secure-modernhttpclient/)

### What the library do?

- Minimum SSL protocol to TLS 1.2
- TLS Mutual Authentication (2-Way Certificate Pinning).

### TLS Mutual Authentication
 
By default, when making a TLS connection, the client check two things:
 
- The server’s certificate matches the requested hostname.
- The server’s certificate has a chain of trust back to a trusted root certificate.
 
_What it doesn’t do is to check if the certificate is the specific certificate you know your server is using, and that’s a security vulnerability._
 
If the client is compromised and a unsafe certificate is installed, someone could do a **man-in-the-middle attack**.
 
**The solution** to this problem is **certificate pinning**, which defends against attacks on certificate authorities and also prevents connections through man-in-the-middle certificate authorities either known or unknown to the application's user.

Storing a certificate on our client apps ensures that any SSL request made matches the one our server has but, this means you are only securing the client side with one way pinning.

Let's ensure the backend receives a valid certificate from the client for **TLS Mutual Authentication** during SSL Handshake:

![Certificate_Pinning.png](https://github.com/alexrainman/secure-modernhttpclient/blob/master/Certificate_Pinning.png)
 
### How it will be achieved?
 
**iOS**: NSUrlSession
 
NSURLSession supports the HTTP/1.1, SPDY, and HTTP/2 protocols. HTTP/2 support is described by RFC 7540, and requires a server supporting either ALPN or NPN for protocol negotiation.

Starting in iOS 9.0 and OS X 10.11, a new security feature called **App Transport Security (ATS)** is enabled by default for all HTTP connections made with NSURLSession. ATS requires that HTTP connections use HTTPS (RFC 2818).
 
App Transport Security (ATS) is available to apps and app extensions, and is enabled by default. It improves privacy and data integrity by ensuring your app’s network connections employ only industry-standard protocols and ciphers without known weaknesses so, your app does not accidentally leak transmitted data to malicious parties.
 
**Android**: OkHttp3

OkHttp3 is an HTTP client that’s efficient by default:

- HTTP/2 support allows all requests to the same host to share a socket.
- Connection pooling reduces request latency (if HTTP/2 isn’t available).
- Transparent GZIP shrinks download sizes.
- Response caching avoids the network completely for repeat requests.

OkHttp3 perseveres when the network is troublesome: it will silently recover from common connection problems. If your service has multiple IP addresses OkHttp3 will attempt alternate addresses if the first connect fails. This is necessary for IPv4+IPv6 and for services hosted in redundant data centers. OkHttp initiates new connections with modern TLS features (SNI, ALPN), and falls back to TLS 1.0 if the handshake fails.

Using OkHttp3 is easy. Its request/response API is designed with fluent builders and immutability. It supports both synchronous blocking calls and async calls with callbacks.
 
The TLS versions and cipher suites in each spec can change with each OkHttp3 release. For example, in OkHttp 2.2 support for SSL 3.0 was dropped in response to the POODLE attack, and in OkHttp 2.3 support for RC4 was dropped.

To check how secure OkHttp3 client is, click [here](https://www.cvedetails.com/vulnerability-list/vendor_id-17165/product_id-41238/Squareup-Okhttp3.html)

### Validating Server Certificate

When the client receives the server certificate (SSL Handshake step (3)), the certificate is validated:

- The certificate chain needs to contain at least the root certificate.
- Test if the certificate chains to a Trusted Root Authority.
- Certificate subject CN host needs to match the request host.
- Check time validity of certificate (not expired).

If these checks don't generate ```SslPolicyErrors```, the root certificate is compared to the _Server Certificate Reference_:

- Server certificate subject must contain the reference certificate subject CN (Common Name).
- Server certificate issuer must contain the reference certificate issuer CN and O (Organization Name).
- Server certificate Thumbprint must be equal to the reference certificate Thumbprint.

If the validation returns ```true```, it means the server certificate matches the one referenced in the app.

### Sending Client certificate

On SSL Handshake step (5), the client certificate is sent to the server and verified on step (6).

To add the client certificate to the platform specific TrustStore, the certificate, in ```pfx``` format, Base64 and its passphrase are required.

A certificate in pfx format can be created from ```client.crt```, ```client.key``` and a ```passphrase``` using openssl:

```
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt
```

Convert ```pfx``` certificate to Base64 using PowerShell:

```
$fileContentBytes = get-content 'path-to\client.pfx' -Encoding Byte
[System.Convert]::ToBase64String($fileContentBytes) | Out-File 'path-to\pfx-bytes.txt'
```

### How to use?

During development, make an https call using a random server certificate Base64 and the library will write the server root certificate raw data to the console:

```
SERVER_CERT_REF=server_cert_base64
```

```cs
// Root server certificate as Base64
var rawServerCertData = "SERVER_CERT_BASE64";
var serverCertBytes = Convert.FromBase64String(rawServerCertData);
var serverCertificateRef = new X509Certificate2(serverCertBytes);

// Client certificate in pfx format as Base64 and its passphrase
var pfxData = "CLIENT_PFX_CERT_BASE64";
var pfxPassphrase = "CLIENT_PFX_CERT_PASSPHRASE";

var handler = new NativeMessageHandler(pfxData, pfxPassphrase, serverCertificateRef)
{
    DisableCaching = true,
    Timeout = new TimeSpan(0, 0, 9)
};
var client = new HttpClient(handler);
```

### Azure App Services (server)

Enable Incoming Client Certificates on SSL Settings:

![azure_ssl.png](https://github.com/alexrainman/secure-modernhttpclient/blob/master/azure_ssl.png)

And, in you Web App web.config file:

```xml
<configuration>
   <appSettings>
      <add key="certificate.subject" value="CN=o*.SERVER_HOST"/>
      <add key="certificate.issuerCN" value="CN=*.SERVER_HOST"/>
      <add key="certificate.issuerOU" value="OU=ISSUER_NAME"/>
      <add key="certificate.issuerO" value="O=ISSUER_ORGANIZATION"/>
      <add key="certificate.thumbprint" value="CERT_THUMBPRINT"/> 
   </appSettings>
</configuration>
```

Where each key will match the certificate you will be sending from the client app.
