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

#### What can happen if my application is vulnerable?

If a vulnerable HTTP client makes an outgoing HTTP connection, while running in a server-side CGI application, an
attacker may be able to:

* Proxy the outgoing HTTP requests made by the web application
* Direct the server to open outgoing connections to an address and port of their choosing
* Tie up server resources by forcing the vulnerable software to use a malicious proxy

If a server is vulnerable, it is extremely easy to exploit in basic form. And we expect security
researchers to be able to scan for this vulnerability very easily and very quickly.

Luckily, if you read on and find you are affected, [easy mitigations](#fix-now) are available.









## What Is Affected {#affected-summary}
{: .section}

Two things are necessary to be vulnerable:

* Code running under a CGI-like context, where `HTTP_PROXY` becomes a real or emulated environment variable
* An HTTP client that trusts `HTTP_PROXY`, and configures it as the proxy, used within a request handler

For example, the confirmed cases we've found so far:

Language | Environment | HTTP client
--- | --- | ---
PHP | php-fpm |Guzzle >=4.0
| mod_php |
Python | wsgiref.handlers.CGIHandler | requests
| twisted.web.twcgi.CGIScript |
Go | net/http/cgi | net/http
{: .table}

But obviously there may be languages we haven't considered yet. CGI is a common standard, and
`HTTP_PROXY` seems to be becoming more popular over time. Take the below as a sample of the most
commonly affected scenarios:


### PHP

* Whether you are vulnerable depends on your specific application code and PHP libraries, but the problem
  seems fairly widespread throughout the ecosystem (and poorly documented)
    * So, this vulnerability affects any version of PHP!
    * It may even affect exotic PHP variants because of how PHP's SAPI system works.
* It is present in Guzzle, Elastica, and probably many, many libraries
    * Guzzle versions after 4.0.0rc2 are vulnerable in all configurations we've tested
    * Elastica seems to be vulnerable under HHVM only
* Just _using_ one of the vulnerable libraries, while processing a user's request, is exploitable.

So, for example, if you are using a Drupal plugin that uses Guzzle 6, you are vulnerable to the request
   that plugin makes being "httpoxied".


### Python

* Python code *must be deployed under CGI to be vulnerable*. Usually, that'll mean the vulnerable code
uses the `wsgiref.handlers.CGIHandler` package
  * Like with Go, actual CGI isn't considered a normal way of deploying Python web applications
  * wsgi, for example, is not vulnerable, because os.environ is not polluted by CGI data
* The 'requests' module will trust and use `os.environ['HTTP_PROXY']`


### Go

* Go code *must be deployed under CGI to be vulnerable*. Usually, that'll mean the vulnerable code uses
the `net/http/cgi` package.
  * This is not considered a usual way of deploying Go to serve HTTP, so this will probably be a much rarer
  case of the vulnerability than PHP applications.
  * Go's `fcgi` package, by comparison, doesn't set actual environment variables (and uses a goroutine to handle
  requests instead of PHP's entire process) it is *not* vulnerable
* Vulnerable versions of `net/http` will trust and use `HTTP_PROXY` for outgoing requests, without checking
if a CGI environment is present









## Immediate Mitigation {#fix-now}
{: .section}

The best immediate mitigation without patching libraries is to block `Proxy` request headers upstream of your application.
There's no legitimate use for this header that we know of, so feel free.
How you do so depends on your web or CGI server:

### Nginx/FastCGI {#mitigate-nginx}

Use this to block the header from being passed on to PHP-FPM, PHP-PM etc.

```
fastcgi_param HTTP_PROXY "";
```

In FastCGI configurations, PHP and "[simple CGI](https://www.nginx.com/resources/wiki/start/topics/examples/simplecgi/)"
are vulnerable (but many other languages that use Nginx FastCGI are not). There's no use for that header, though,
so you _may as well block it anyway_.

### Apache/mod_cgi {#mitigate-apache}

In this configuration, languages like Go and Python may be vulnerable (the `HTTP_PROXY` env var is "real"). If you are
using **mod_headers**, you can unset the Proxy header with this directive:

```
RequestHeader unset Proxy
```

If you are using **mod_security**, you can use a `SecRule` to deny traffic with a `Proxy` header. Here's an example,
vary the action to taste, and make sure `SecRuleEngine` is on. The 1000005 ID has been assigned to this issue.

```
SecRule &REQUEST_HEADERS:Proxy "@gt 0" "id:1000005,log,deny,msg:'httpoxy denied'"
```

### HAProxy {#mitigate-haproxy}

This will strip the header off requests:

```
http-request del-header Proxy
```

### Microsoft IIS with PHP or a CGI framework {#mitigate-iis}

httpoxy does not affect any Microsoft Web Frameworks, e.g. not ASP.NET nor Active Server Pages. But if you have
installed PHP or any other third party framework on top of IIS, we recommend applying mitigation steps to protect from
httpoxy attacks.

Update your `apphost.config` with the following rule:

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

### Other CGI software and applications

Please let us know of other places where httpoxy is found. We'd be happy to help you communicate fixes for your platform,
server or library if you are affected. Contact [contact@httpoxy.org](mailto:contact@httpoxy.org?subject=Fix) or
[@httpoxy](https://twitter.com/httpoxy) to let us know. Or make a PR against the httpoxy-org repo. TODO





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

To put it plainly: there is no way to trust the value of an HTTP_ env var in a CGI environment. They cannot be
distinguished from request headers, in any way. So, _any_ usage of `HTTP_PROXY` in a CGI context is suspicious.

If you need to configure the proxy of a CGI application via an environment variable, use a variable name that will
never conflict with request headers. That is: one that does not begin with `HTTP_`. We strongly recommend you go for
`CGI_HTTP_PROXY`.

#### PHP {#prevent-php}

CLI-only code may safely trust `$_SERVER['HTTP_PROXY']` or `getenv('HTTP_PROXY')`. But bear in mind that code written
for the CLI context often ends up running in a SAPI eventually, particularly utility or library code. And, with open
source code, that might not even be your doing. So, if you are going to rely on `HTTP_PROXY` at all, you should guard
that code with a check of the `PHP_SAPI` constant.







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
under the httpoxy Github organization. TODO






## Why It Happened {#why}
{: .section}

Under the CGI spec, headers are provided mixed into the environment variables. (These are formally known as
"Protocol-Specific Meta-Variables"[^meta-variables]).

The task being completed in most of the vulnerabilities is:
configure a proxy for
the internal (to the web application) HTTP request made shortly after. The same task in Ruby could be completed by
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
 <dt class="col-sm-3">July 2016</dt>
 <dd class="col-sm-9" markdown="1">
  Scott Geary, an engineer at Vend, found an instance of the bug in the wild. The Vend security team found the vulnerability
  was still exploitable in PHP, and present in many modern languages and libraries. We started to disclose to security response teams.
 </dd>
</dl>

So, the bug was lying dormant for years, like a latent infection: pox.




## Thanks and Further Coverage
{: .section}

Over the past two weeks, the Vend security team worked to disclose the issue responsibly to as many affected parties as we
could. We'd like to thank the members of:

* The Red Hat Security Response Team, who provided extremely helpful advice and access to their experience disclosing
  widespread vulnerabilities - if you're sitting on a Big One, they're a great resource to reach out to
* The language and implementation teams, who kept to the disclosure timeline and provided lively discussion

I've put together some more opinionated notes on httpoxy on my Medium account: TODO.

For media enquiries, see [the media
and licensing](media.html) page (TL;DR: [CC0](http://creativecommons.org/publicdomain/zero/1.0/), use what you like, no
permission/attribution necessary).

TODO: sign-off on final content




<small>Page updated at 2016-07-09 03:09 UTC</small>


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

*[PHP]: Popular programming language
*[HTTP]: Hypertext transfer protocol
*[CGI]: Common Gateway Interface: the common name for RFC 3875.
{:.initialism}
*[CGI-like]: For example, PHP's mod_php and fastcgi/php-fpm
*[RFC 3875]: The standardized CGI protocol, published in 2003.
{:.initialism}
