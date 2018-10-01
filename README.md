# Secure ModerHttpClient

### What the library enforces?

- Authorization Header is required.
- Cache is disabled by default.
- TLS Mutual Authentication.

### Avoiding man-in-the-middle attacks
 
By default, when making a TLS connection, the client check two things:
 
- The server’s certificate matches the requested hostname.
- The server’s certificate has a chain of trust back to a trusted root certificate.
 
_What it doesn’t do is to check if the certificate is the specific certificate you know your server is using, and that’s a security vulnerability._
 
If the client is compromised and a unsafe certificate is installed, someone could do a **man-in-the-middle attack**.
 
**The solution** to this problem is **certificate pinning**: defends against attacks on certificate authorities and also prevents connections through man-in-the-middle certificate authorities either known or unknown to the application's user.

Storing a certificate on our client apps ensures that any SSL request made matches the one our server has but, this means you are only securing the client side with one way pinning.

Let's ensure the backend receives a valid certificate from the client for a  **TLS Mutual Authentication** and **2-Way** Certificate Pinning during SSL Handshake:


 
### How it will be achieved?

This library brings the latest platform-specific networking libraries to Xamarin applications via a custom HttpClient handler.
 
**iOS**: NSUrlSession
 
NSURLSession supports the HTTP/1.1, SPDY, and HTTP/2 protocols. HTTP/2 support is described by RFC 7540, and requires a server supporting either ALPN or NPN for protocol negotiation.

Starting in iOS 9.0 and OS X 10.11, a new security feature called **App Transport Security (ATS)** is enabled by default for all HTTP connections made with NSURLSession. ATS requires that HTTP connections use HTTPS (RFC 2818).
 
App Transport Security (ATS) is available to apps and app extensions, and is enabled by default. It improves privacy and data integrity by ensuring your app’s network connections employ only industry-standard protocols and ciphers without known weaknesses. This helps instill user trust that your app does not accidentally leak transmitted data to malicious parties.

By configuring this key’s value in your app’s _Info.plist_ file, you can customize the security of your network connections in a variety of ways:

- Allow insecure communication with particular servers, while maintaining ATS protections elsewhere in your app, which we will not do.
- Allow insecure loads for web views or for media, while maintaining ATS protections elsewhere in your app, which we will not do.
- Enable new security features such as Certificate Transparency (to be explored)

Security scans can verify that:

- ```NSExceptionAllowsInsecureHTTPLoads``` is always false (never support HTTP)
- ```NSExceptionRequiresForwardSecrecy``` is always true (not overriding the requirement that a server support perfect forward secrecy (PFS) which limits the accepted ciphers)
- ```NSRequiresCertificateTransparency``` default is false but if set to true, requires that valid, signed Certificate Transparency (CT) timestamps, from known CT logs, be presented for server (X.509) certificates on a domain.
 
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

### 2-Way Certificate Pinning

Pre-flow:

- Set minimum SSL protocol to TLS 1.2
- For performance reasons, SSL certificate verification via ServicePointManager is disabled by default:

```cs
ServicePointManager.ServerCertificateValidationCallback = null;
```

When the client receives the server certificate (SSL Handshake step (3)), the certificate is validated:

- The certificate chain needs to contain at least the root certificate.
- Test if the certificate chains to a Trusted Root Authority.
- Certificate subject CN host needs to match the request host.
- Check time validity of certificate (not expired).

If these checks don't generate ```SslPolicyErrors```, the root certificate is compared to the _Server Certificate Reference_:

- Server certificate subject must contain the reference certificate subject CN (Common Name).
- Server certificate issuer must contain the reference certificate issuer CN and O (Organization Name).
- Server certificate Thumbprint must be equal to the reference certificate Thumbprint.

If the validation returns ```true```, meaning the server certificate is valid, the app sends the client certificate to the server.

### Client certificate

On SSL Handshake step (5), the client certificate is sent to the server and verified on step (6).

To be able to add the client certificate to the platform specific TrustStore, the certificate in ```pfx``` format and its passphrase are required.

```cs
// iOS (NSUrlSession)
// DataTaskDelegate.DidreceiveChallenge will send client credentials.certificate when challenge = AuthenticationMethodClientCertificate is received
var pfxDataBytes = Convert.FromBase64String(pfxData);
var options = NSDictionary.FromObjectsAndKeys(new object[] { pfxPassphrase }, new object[] { "passphrase" });
var status = SecImportExport.ImportPkcs12(pfxDataBytes, options, out NSDictionary[] items);
var identityRef = items[0]["identity"];
var identity = new SecIdentity(identityRef.Handle);
SecCertificate[] certs = { identity.Certificate };
var credentials = new NSUrlCredential(identity, certs, NSUrlCredentialPersistence.ForSession);

// Android (OkHttp3)
// Add client certificate to TrustStore       
var pfxDataBytes = Convert.FromBase64String(pfxData);
var stream = new System.IO.MemoryStream(pfxDataBytes);
KeyStore keyStore = KeyStore.GetInstance("PKCS12");
keyStore.Load(stream, pfxPassphrase.ToCharArray());
var kmf = KeyManagerFactory.GetInstance("X509");
kmf.Init(keyStore, pfxPassphrase.ToCharArray());
IKeyManager[] keyManagers = kmf.GetKeyManagers();
SSLContext sslContext = SSLContext.GetInstance("TLS");
sslContext.Init(keyManagers, null, null);
clientBuilder.SslSocketFactory(sslContext.SocketFactory);
```

### How to use?

```cs
// Root server certificate as Base64
var rawServerCertData = "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";
var serverCertBytes = Convert.FromBase64String(rawServerCertData);
var serverCertificateRef = new X509Certificate2(serverCertBytes);

// Client certificate in pfx format as Base64 and its passphrase
var pfxData = "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";
var pfxPassphrase = "xxxxxxxxxx";

var handler = new NativeMessageHandler(pfxData, pfxPassphrase, serverCertificateRef);
var client = new HttpClient(handler);
```

### Postman (client)

TODO

### Azure App Services (server)

Enable Incoming Client Certificates on SSL Settings:

![Screen Shot 2018-09-19 at 12.03.13 PM.png](/.attachments/Screen%20Shot%202018-09-19%20at%2012.03.13%20PM-9f4d68f3-85c6-424c-b912-a088b537da83.png)

And, in you Web App web.config file:

```xml
<configuration>
   <appSettings>
      <add key="certificate.subject" value="CN=o*.teamworkcards-api-prod.p.azurewebsites.net"/>
      <add key="certificate.issuerCN" value="CN=*.teamworkcards-api-prod.p.azurewebsites.net"/>
      <add key="certificate.issuerOU" value="OU=Mobility Solutions"/>
      <add key="certificate.issuerO" value="O=Schlumberger"/>
      <add key="certificate.thumbprint" value="A4212A08E1F039BDBD1A908999C99A61F0E5883A"/> 
   </appSettings>
</configuration>
```

Where each key will match the certificate you will be sending from the client app.

### Apigee (server)

TODO

### Requirements

Server Certificate reference (root)

- During setup, use any raw ServerCertData. Run the app once making an HTTPS call and the library will write the server root certificate raw data as Base64 to the console.

```
SERVER_CERT_REF=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
```

Client certificate in ```pfx``` format and its passphrase.

- A certificate in pfx format can be created from ```client.crt```, ```client.key``` and a ```passphrase``` using openssl:

```
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt
```

- Convert ```pfx``` certificate to Base64 using PowerShell:

```
$fileContentBytes = get-content 'C:\Users\areyes27\Desktop\client.pfx' -Encoding Byte
[System.Convert]::ToBase64String($fileContentBytes) | Out-File 'C:\Users\areyes27\Desktop\pfx-bytes.txt'
``` 

The server root certificate reference, the client certificate as Base64 and its passphrase will be provisioned to the app using [Intune MAM app configuration](https://docs.microsoft.com/en-us/intune/app-configuration-policies-overview).

Notice that ```Security settings``` is one of the use cases for app configuration policies.
