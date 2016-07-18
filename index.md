---
layout: default
---

*httpoxy* is a set of vulnerabilities that affect application code running in CGI, or CGI-like environments. It comes
down to a simple namespace conflict:
{: .lead}

* RFC 3875 (CGI) puts the HTTP `Proxy` header from a request into the environment variables as `HTTP_PROXY`
* `HTTP_PROXY` is a popular environment variable used to configure an outgoing proxy
{: .lead}

This leads to a remotely exploitable vulnerability. If you're running PHP or CGI, you should ***block the `Proxy` header***
now. [Here's how.](#fix-now)
{: .lead}

httpoxy is a vulnerability for server-side web applications. If you're not deploying code, you don't need to worry.

#### What can happen if my web application is vulnerable?

If a vulnerable HTTP client makes an outgoing HTTP connection, while running in a server-side CGI application, an
attacker may be able to:

* Proxy the outgoing HTTP requests made by the web application
* Direct the server to open outgoing connections to an address and port of their choosing
* Tie up server resources by forcing the vulnerable software to use a malicious proxy

httpoxy is extremely easy to exploit in basic form. And we expect security
researchers to be able to scan for it quickly. Luckily, if you read on and
find you are affected, [easy mitigations](#fix-now) are available.







## What Is Affected {#affected-summary}
{: .section}

A few things are necessary to be vulnerable:

* Code running under a CGI-like context, where `HTTP_PROXY` becomes a real or emulated environment variable
* An HTTP client that trusts `HTTP_PROXY`, and configures it as the proxy
* That client, used within a request handler, making an HTTP (as opposed to HTTPS) request

For example, the confirmed cases we've found so far:

Language | Environment | HTTP client
--- | --- | ---
PHP | php-fpm <br /> mod_php | Guzzle 4+ <br /> Artax
Python | wsgiref.handlers.CGIHandler <br /> twisted.web.twcgi.CGIScript | requests
Go | net/http/cgi | net/http
{: .table}

But obviously there may be languages we haven't considered yet. CGI is a common standard, and
`HTTP_PROXY` seems to be becoming more popular over time. Take the below as a sample of the most
commonly affected scenarios:


### PHP

* Whether you are vulnerable depends on your specific application code and PHP libraries, but the problem
  seems fairly widespread
* Just _using_ one of the vulnerable libraries, while processing a user's request, is exploitable.
* If you're using a vulnerable library, this vulnerability will affect any version of PHP
    * It even affects alternative PHP runtimes such as HHVM deployed under FastCGI
* It is present in Guzzle, Artax, and probably many, many libraries
    * Guzzle versions after 4.0.0rc2 are vulnerable, Guzzle 3 and below is not.
    * Another example is in Composer's StreamContextBuilder utility class

So, for example, if you are using a Drupal module that uses Guzzle 6 and makes an outgoing HTTP request (for example,
to check a weather API), you are vulnerable to the request that plugin makes being "httpoxied".

### Python

* Python code *must be deployed under CGI to be vulnerable*. Usually, that'll mean the vulnerable code
will use a CGI handler like `wsgiref.handlers.CGIHandler`
  * This is not considered a normal way of deploying Python webapps (most people are using WSGI or FastCGI, both of which are
  not affected), so vulnerable Python applications will probably be much rarer than vulnerable PHP applications.
  * wsgi, for example, is not vulnerable, because os.environ is not polluted by CGI data
* Vulnerable versions of the requests library will trust and use `os.environ['HTTP_PROXY']`, without checking if CGI is in use

### Go

* Go code *must be deployed under CGI to be vulnerable*. Usually, that'll mean the vulnerable code uses
the `net/http/cgi` package.
  * As with Python, this is not considered a usual way of deploying Go as a web application, so this vulnerability should be
  relatively rare
  * Go's `net/http/fcgi` package, by comparison, does not set actual environment variables, so it is *not* vulnerable
* Vulnerable versions of `net/http` will trust and use `HTTP_PROXY` for outgoing requests, without checking if CGI is in use







## Immediate Mitigation {#fix-now}
{: .section}

The best immediate mitigation is to block `Proxy` request headers as early as possible, and before they hit your
application. This is easy and safe.
{: .lead}

* It's safe because the `Proxy` header is undefined by the IETF, and isn't listed on the
[IANA's registry of message headers](http://www.iana.org/assignments/message-headers/message-headers.xhtml). This means
<strong>there is no standard use for the header at all</strong>; not even a provisional use-case.
* Standards-compliant HTTP clients and servers will never read or send this header.
* You can either strip the header or completely block requests attempting to use it.
* You should try to do your mitigation as *early* and as far *upstream* as you can.
    * Do it "at the edge", where HTTP requests first enter your system.
    * That way, you can fix lots of vulnerable software at once.
    * Everything behind a reverse proxy or application firewall that strips the `Proxy` header is safe!

How you block a `Proxy` header depends on the specifics of your setup. The earliest convenient place to block the header
might be at a web application firewall device, or directly on the webserver running Apache or Nginx. Here are a few of
the more common mitigations:


### Nginx/FastCGI {#mitigate-nginx}

Use this to block the header from being passed on to PHP-FPM, PHP-PM etc.

```
fastcgi_param HTTP_PROXY "";
```

In FastCGI configurations, PHP is vulnerable (but many other languages that use Nginx FastCGI are not).

### Apache {#mitigate-apache}

For specific Apache coverage (and details for other Apache software projects like Tomcat), we strongly recommend
you read the [Apache Software Foundation's official advisory](https://www.apache.org/security/asf-httpoxy-response.txt) on
the matter. The very basic mitigation information you'll find below is covered in much greater depth there.

If you're using Apache HTTP Server with `mod_cgi`, languages like Go and Python may be vulnerable (the `HTTP_PROXY` env var
is "real"). And `mod_php` is affected due to the nature of PHP. If you are using **mod_headers**, you can unset the
`Proxy` header before further processing with this directive:

```
RequestHeader unset Proxy early
```

If you are using **mod_security**, you can use a `SecRule` to deny traffic with a `Proxy` header. Here's an example,
vary the action to taste, and make sure `SecRuleEngine` is on. The 1000005 ID has been assigned to this issue.

```
SecRule &REQUEST_HEADERS:Proxy "@gt 0" "id:1000005,log,deny,msg:'httpoxy denied'"
```

Finally, if you're using Apache Traffic Server, it's not affected, but you can use it to strip the Proxy header; very helpful
for any services sitting behind it. Again, see the [ASF's guidance](https://www.apache.org/security/asf-httpoxy-response.txt).

### HAProxy {#mitigate-haproxy}

This will strip the header off requests:

```
http-request del-header Proxy
```

### Varnish {#mitigate-varnish}

For Varnish, the following should unset the header. Add it to the pre-existing vcl_recv section:

```
sub vcl_recv {
    [...]
    unset req.http.proxy;
    [...]
}
```

### OpenBSD relayd {#mitigate-relayd}

For relayd, the following should remove the header. Add it to a pre-existing filter:

```
http protocol httpfilter {
        match request header remove "Proxy"
}
```

### Microsoft IIS with PHP or a CGI framework {#mitigate-iis}

httpoxy does not affect any Microsoft Web Frameworks, e.g. not ASP.NET nor Active Server Pages. But if you have
installed PHP or any other third party framework on top of IIS, we recommend applying mitigation steps to protect from
httpoxy attacks.

Update your `ApplicationHost.config` with the following rule:

```xml
<system.webServer>
    <rewrite>
        <rules>
            <rule name="Erase HTTP_PROXY" patternSyntax="Wildcard">
                <match url="*.*" />
                <serverVariables>
                    <set name="HTTP_PROXY" value="" />
                </serverVariables>
                <action type="None" />
            </rule>
        </rules>
    </rewrite>
</system.webServer>
```

You may want to use `<globalRules>` instead of `<rules>` - see the
[IIS documentation on rewrite rule scope](http://www.iis.net/learn/extensions/url-rewrite-module/url-rewrite-module-configuration-reference#Rewrite_Rules_Scope).

### Other CGI software and applications

Please let us know of other places where httpoxy is found. We'd be happy to help you communicate fixes for your platform,
server or library if you are affected. Contact [contact@httpoxy.org](mailto:contact@httpoxy.org?subject=Fix) or
[@httpoxy](https://twitter.com/httpoxy) to let us know. Or make a PR against the [httpoxy-org repo](https://github.com/httpoxy/httpoxy-org).





## Ineffective fixes in PHP {#php-nope}
{: .section}

Userland PHP fixes don't work. Don't bother:

* Using `unset($_SERVER['HTTP_PROXY'])` does not affect the value returned from `getenv()`, so is not an effective
  mitigation
* Using `putenv('HTTP_PROXY=')` does not work either (to be precise: it only works if that value is coming from an
  actual environment variable rather than a header -- so, it cannot be used for mitigation)










## Prevention {#prevent}
{: .section}

### Summary

* If you can avoid it, do not deploy into environments where the CGI data is merged into the actual environment variables
* Use and expect `CGI_HTTP_PROXY` to set the proxy for a CGI application's internal requests, if necessary
    * You can still support `HTTP_PROXY`, but you must assert that CGI is not in use
    * In PHP, check `PHP_SAPI == 'cli'`
    * Otherwise, a simple check is to not trust `HTTP_PROXY` if `REQUEST_METHOD` is also set. RFC 3875 seems to require
      this meta-variable:

      {:.blockquote}
      > <p class="m-b-0" markdown="1">
      >  The `REQUEST_METHOD` meta-variable MUST be set to the method which should be used by the script to process the request
      > </p>

### Don't Trust `HTTP_PROXY` Under CGI

To put it plainly: there is no way to trust the value of an `HTTP_` env var in a CGI environment. They cannot be
distinguished from request headers according to the specification. So, _any_ usage of `HTTP_PROXY` in a CGI context is
suspicious.

If you need to configure the proxy of a CGI application via an environment variable, use a variable name that will
never conflict with request headers. That is: one that does not begin with `HTTP_`. We strongly recommend you go for
`CGI_HTTP_PROXY`. (As seen in Ruby and libwww-perl's mitigations for this issue.)

### PHP {#prevent-php}

CLI-only code may safely trust `$_SERVER['HTTP_PROXY']` or `getenv('HTTP_PROXY')`. But bear in mind that code written
for the CLI context often ends up running in a SAPI eventually, particularly utility or library code. And, with open
source code, that might not even be your doing. So, if you are going to rely on `HTTP_PROXY` at all, you should guard
that code with a check of the `PHP_SAPI` constant.

### Network Configuration as Prevention

A defense-in-depth strategy that can combat httpoxy (and entire classes of other security problems) is to severely restrict
the outgoing requests your web application can make to an absolute minimum. For example, if a web application is
firewalled in such a way that it *cannot* make outgoing HTTP requests, an attacker will not be able to receive
the "misproxied" requests (because the web application is prevented from connecting to the attacker).

### HTTPS

And, of course, another defense-in-depth strategy that works is to use HTTPS for internal requests, not just for
securing your site's connections to the outside world. Those aren't affected by `HTTP_PROXY`.





## How It Works {#how-it-works}
{: .section}

Using PHP as an example, because it is illustrative. PHP has a method called `getenv()`[^php-getenv].

There is a common vulnerability in many PHP libraries and applications, introduced by confusing
`getenv` for a method that only returns environment variables. In fact, getenv() is closer to the
`$_SERVER` superglobal: it contains both environment variables and user-controlled data.

Specifically, when PHP is running under a CGI-like server, the HTTP request headers (data supplied
 by the client) are merged into the `$_SERVER` superglobal under keys beginning with `HTTP_`. This is
 the same information that `getenv` reads from.

When a user sends a request with a `Proxy` header, the header appears to the PHP application as `getenv('HTTP_PROXY')`.
Some common PHP libraries have been trusting this value, even when run in a CGI/SAPI environment.

Reading and trusting `$_SERVER['HTTP_PROXY']` is exactly the same vulnerability, but tends to happen much less often
(perhaps because of getenv's name, perhaps because the semantics of the `$_SERVER` superglobal are better understood among
the community).

### Minimal example code {#examples}

Note that these examples require deployment into a vulnerable environment before there is actually a vulnerability
(e.g. php-fpm, or Apache's `ScriptAlias`)

#### PHP

```php?start_inline=1
$client = new GuzzleHttp\Client();
$client->get('http://api.internal/?secret=foo')
```

#### Python

```python
from wsgiref.handlers import CGIHandler
def application(environ, start_response):
    requests.get("http://api.internal/?secret=foo")
CGIHandler().run(application)
```

#### Go

```go
cgi.Serve(
    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        res, _ := http.Get("http://api.internal/?secret=foo")
        // [...]
```

More complete PoC repos (using Docker, and testing with an actual listener for the proxied request) have been prepared
under the [httpoxy Github organization](https://github.com/httpoxy).






## Why It Happened {#why}
{: .section}

Under the CGI spec, headers are provided mixed into the environment variables. (These are formally known as
"Protocol-Specific Meta-Variables"[^meta-variables]). That's just the way the spec works, not a failure or bug.

The goal of the code, in most of the vulnerabilities, is to find the correct proxy to use, when auto-configuring a
client for the internal  HTTP request made shortly after. This task in Ruby could be completed by
the `find_proxy` method of `URI::Generic`, which notes:

> <p class="m-b-0" markdown="1">
>
> `http_proxy` and `HTTP_PROXY` are treated specially under the CGI environment, because `HTTP_PROXY` may be set by Proxy:
> header. So `HTTP_PROXY` is not used. `http_proxy` is not used too if the variable is case insensitive. `CGI_HTTP_PROXY`
> can be used instead.
>
> </p>
> <footer class="blockquote-footer">
> From the <cite title="Source Title"><a href="http://ruby-doc.org/stdlib-2.3.1/libdoc/uri/rdoc/URI/Generic.html#method-i-find_proxy">Ruby stdlib documentation</a></cite>
> </footer>
{: .blockquote}

Other instances of the same vulnerability are present in other languages. For example, when
using Go's `net/http/cgi` module, and deploying as a CGI application. This indicates the vulnerability
is a standard danger in CGI environments.





## History of httpoxy {#history}
{: .section}

This bug was first discovered over 15 years ago. The timeline goes something like:

<dl class="dl-horizontal row">
 <dt class="col-sm-3">March 2001</dt>
 <dd class="col-sm-9" markdown="1">
  The issue is discovered in libwww-perl and fixed. Reported by Randal L. Schwartz. [^perl-bug]
 </dd>
 <dt class="col-sm-3">April 2001</dt>
 <dd class="col-sm-9" markdown="1">
  The issue is discovered in curl, and fixed there too (albeit probably not for Windows). Reported by Cris Bailiff. [^curl-bug]
 </dd>
 <dt class="col-sm-3">July 2012</dt>
 <dd class="col-sm-9" markdown="1">
  In implementing `HTTP_PROXY` for `Net::HTTP`, the Ruby team notice and avoid the potential issue. Nice work Akira Tanaka! [^ruby-ref]
 </dd>
 <dt class="col-sm-3">November 2013</dt>
 <dd class="col-sm-9" markdown="1">
  The issue is mentioned on the nginx mailing list. The user humbly points out the issue: "unless
     I'm missing something, which is very possible". No, Jonathan Matthews, you were exactly right! [^nginx-ref]
 </dd>
 <dt class="col-sm-3">February 2015</dt>
 <dd class="col-sm-9" markdown="1">
   The issue is mentioned on the Apache httpd-dev mailing list. Spotted by Stefan Fritsch. [^apache-ref]
  </dd>
 <dt class="col-sm-3">July 2016</dt>
 <dd class="col-sm-9" markdown="1">
  Scott Geary, an engineer at Vend, found an instance of the bug in the wild. The Vend security team found the vulnerability
  was still exploitable in PHP, and present in many modern languages and libraries. We started to disclose to security response teams.
 </dd>
</dl>

So, the bug was lying dormant for years, like a latent infection: pox. We imagine that many people may have found the issue over
the years, but never investigated its scope in other languages and libraries. If you've found a historical discussion
of interest that we've missed, let us know.



## CVEs    {#cve}
{: .section}

httpoxy has a number of CVEs assigned. These cover the cases where

* a language or CGI implementation makes the `Proxy` header available in such a way that the application cannot tell whether
  it is a real environment variable, or
* an application trusts the value of the `HTTP_PROXY` environment variable by default in a CGI environment (but only where that application should have been
able to tell it came from a request)

The assigned CVEs so far:

* CVE-2016-5385: PHP
* CVE-2016-5386: Go
* CVE-2016-5387: Apache HTTP Server
* CVE-2016-5388: Apache Tomcat
* CVE-2016-1000109: HHVM
* CVE-2016-1000110: Python

We suspect there may be more CVEs coming for httpoxy, as less common software is checked over. If you
want to get a CVE assigned for an httpoxy issue, there are a couple of options:

  - For open source code projects, you can use the [Distributed Weakness Filing Project](https://distributedweaknessfiling.org/) (DWF).
    They have a simple way to report (public) issues using the form at [iwantacve.org](https://iwantacve.org/)
  - For closed source code projects, you can talk to [MITRE, or one of their participating CNAs/vendors/coordinators](https://cve.mitre.org/cve/cna.html).




## Thanks and Further Coverage
{: .section}

We'll be linking to official announcements from affected teams here, as they become available.

* [The CERT vulnerability note - VU#797896](https://www.kb.cert.org/vuls/id/797896)
* [Red Hat advisory](https://access.redhat.com/security/vulnerabilities/httpoxy)
* [The Apache Software Foundation advisory](https://www.apache.org/security/asf-httpoxy-response.txt)
* [nginx blog post](https://www.nginx.com/blog/mitigating-the-httpoxy-vulnerability-with-nginx/)
* [Drupal advisory](https://www.drupal.org/SA-CORE-2016-003)
* [Fastly advisory]( https://www.fastly.com/security-advisories/vulnerability-use-httpproxy-cgi)
* [Cloudflare blog post](https://blog.cloudflare.com/cloudflare-sites-protected-from-httpoxy/)
* [Akamai blog post](https://blogs.akamai.com/2016/07/akamai-mitigates-httpoxy-vulnerability.html)

Over the past two weeks, the Vend security team worked to disclose the issue responsibly to as many affected parties as we
could. We'd like to thank the members of:

* The Red Hat Product Security team, who provided extremely useful advice and access to their experience disclosing
  widespread vulnerabilities - if you're sitting on a big or complicated disclosure, they're a great resource to reach
  out to for help.
* The language and implementation teams, who kept to disclosure norms and provided lively discussion.

There's an [extra](extra.html) page with some meta-discussion on the whole named disclosure thing and contact details.
The content on this page is licensed as [CC0](http://creativecommons.org/publicdomain/zero/1.0/) (TL;DR: use what you
like, no permission/attribution necessary).

I've put together some more opinionated notes on httpoxy on [my Medium account](https://medium.com/@nzdominic).

Regards,<br />
Dominic Scheirlinck and the httpoxy disclosure team


<small>
    Page updated at 2016-07-18 19:43 UTC
</small>


## References
{: .section}

[^php-getenv]:
    [The PHP documentation manual page for getenv](https://secure.php.net/getenv)

[^meta-variables]:
    [RFC 3875 4.1.18: Protocol-Specific Meta-Variables](https://tools.ietf.org/html/rfc3875#section-4.1.18)

[^perl-bug]:
    The fix applied correctly handles cases with case-insensitive environment variables.
    [libwww-perl-5.51 announcement](http://www.nntp.perl.org/group/perl.libwww/2001/03/msg2249.html)

[^curl-bug]:
    The [fix applied to Curl](https://sourceforge.net/p/curl/bugs/66/) does not
    correctly handle cases with case-insensitive environment variables - it specifically mentions the fix would not
    be enough for "NT" (Windows). The commit itself carries the prescient message "[since it might become
    a security problem](https://github.com/curl/curl/commit/18f044f19d26f2b6dcd41796966f488a62a1bdca)."

[^ruby-ref]:
    The [mitigation in Ruby](https://bugs.ruby-lang.org/issues/6546), like that for libwww-perl, correctly handles
    case-insensitive environment variables.

[^nginx-ref]:
    The [nginx mailing list](https://forum.nginx.org/read.php?2,244407,244485#msg-244485) even had a PHP-specific
    explanation.

[^apache-ref]:
    [Discussed](http://mail-archives.apache.org/mod_mbox/httpd-dev/201502.mbox/%3C2651807.jIIY3NPtlf@k%3E) in reference to CGI specifically.
