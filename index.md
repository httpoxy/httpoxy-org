---
layout: default
---

<header>
    <h1 class="display-1" id="top">httpoxy</h1>

    <h2>
        A CGI application vulnerability
        <small class="text-muted">for PHP, Golang and Python</small>
    </h2>
</header>

## Summary

<p class="lead">
<strong>httpoxy</strong>
is a set of vulnerabilities
affecting code running in
<abbr title="Common Gateway Interface">CGI</abbr>
or CGI-like environments. In essence,
it boils down to a namespace conflict:
</p>

* RFC 3875 (CGI) puts the HTTP `Proxy` header from a request into the environment as `HTTP_PROXY`
* `HTTP_PROXY` is a popular environment variable used to configure an outgoing proxy

If a vulnerable HTTP client, running in a server side process, makes an outgoing connection to an
internal API, a <strong>remote, unauthenticated</strong> attacker may be able to

* Proxy (i.e. silently man-in-the-middle) outgoing HTTP sub-requests made by the server
* Direct the server to open outgoing connections to an address and port of their choosing
* Tie up server resources by forcing the vulnerable software to use a malicious proxy (i.e.
reverse slowloris) etc.

If a server is vulnerable, it is extremely easy to exploit in basic form. And we expect security
 researchers to be able to scan for this vulnerability very easily and very quickly. So, patch your
 software now!

### PHP

Affected:
 <span class="label label-danger">mod_php</span>
 <span class="label label-danger">fastcgi/php-fpm</span>

* This vulnerability affects any version of PHP! It may even affect exotic PHP variants because of how PHP userland works.
* Whether you are vulnerable depends on your specific application code and PHP libraries, but the problem
  seems fairly widespread throughout the ecosystem (and poorly documented)
* It is present in Guzzle, Elastica, and probably many, many libraries
    * Guzzle versions after 4.0.0rc2 are vulnerable in all configurations we've tested
    * Elastica seems to be vulnerable under HHVM only
* Just _using_ one of the vulnerable libraries, while processing a user's request, is exploitable.

So, for example, if you are using a Drupal plugin that uses Guzzle 6, you are vulnerable to the request
   that plugin makes being "httpoxied".

### For Go

Affected:
 <span class="label label-danger">net/http/cgi</span>

Not affected:
 <span class="label label-success">net/http/fcgi</span>
 <span class="label label-success">'normal' deployments</span>

* Go code *must be deployed under CGI to be vulnerable*. Usually, that'll mean the vulnerable code uses
the `net/http/cgi` package.
  * This is not considered a usual way of deploying Go to serve HTTP, so this will probably be a much rarer
  case of the vulnerability than PHP applications.
  * Golang's `fcgi` package, by comparison, doesn't set actual environment variables (and uses a goroutine to handle
  requests instead of PHP's entire process) it is *not* vulnerable
* Vulnerable versions of `net/http` will trust and use `HTTP_PROXY` for outgoing requests, without checking
if a CGI environment is present

### For Python:

Affected:
 <span class="label label-danger">wsgiref.handlers.CGIHandler</span>

Not affected:
 <span class="label label-success">wsgi in general</span>
 <span class="label label-success">'normal' deployments</span>

* Python code *must be deployed under CGI to be vulnerable*. Usually, that'll mean the vulnerable code
uses the `wsgiref.handlers.CGIHandler` package
  * Like with Golang, actual CGI isn't considered a normal way of deploying Python web applications
  * wsgi, for example, is not vulnerable, because os.environ is not polluted by CGI data
* The 'requests' module will trust and use `os.environ['HTTP_PROXY']`

## Examples
Two things are necessary to be vulnerable:

* Code running under a CGI-like context, where `HTTP_PROXY` becomes a real or emulated environment variable
* An HTTP client that trusts `HTTP_PROXY`, and configures it as the proxy, used within a request handler

For example, the confirmed cases we've found so far:

Language | Environment | HTTP client
--- | --- | ---
PHP | php-fpm |Guzzle >=4.0
| | mod_php | |
Python | wsgiref.handlers.CGIHandler | requests
|  | twisted.web.twcgi.CGIScript |  |
Go | net/http/cgi | net/http

But obviously there may be languages we haven't considered yet. CGI is a common standard, and
`HTTP_PROXY` seems to be becoming more popular over time.

## How it works

Using PHP as an example, because it is illustrative. PHP has a method called `getenv()`.

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

### Minimal example code

Note that these examples require deployment into a vulnerable environment before there is actually a vulnerability
(e.g. php-fpm, or Apache's `ScriptAlias`)

#### PHP

```php
$client = new GuzzleHttp\Client();
$client->get('http://api.internal/?secret=foo')
```

#### Python

```py
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
under the httpoxy Github organization.

## Why has this happened?

getenv() is part of a set of functions designed to work within RFC 3875; known to the rest of us as CGI. And under CGI, that's just how headers are provided: mixed into the environment variables. (These are formally known as "Protocol-Specific Meta-Variables" in the spec.)

The PHP documentation manual for getenv() is misleading; it does mention the RFC by number, but it's lacking the emphasis that would lead to a developer thinking about headers and the potential for a collision with an actual HTTP_ env var. The summary description of the function is just: "Gets the value of an environment variable."

There are instances of developers replacing $_SERVER with getenv, thinking they were fixing a potential bug (when actually, this accomplishes nothing at all).

Finally, the task being completed in most of the vulnerabilities is: configure a proxy for the HTTP request we'll make shortly after. PHP has no built-in method to find the proxy that should be configured, which leads to developers doing it themselves, getting it slightly wrong, and ending up with a major security vulnerability. The same task in Ruby would be completed by the find_proxy method of URI::Generic, which notes:

http_proxy and HTTP_PROXY are treated specially under the CGI environment, because HTTP_PROXY may be set by Proxy: header. So HTTP_PROXY is not used. http_proxy is not used too if the variable is case insensitive. CGI_HTTP_PROXY can be used instead.

This should be rare, but other instances of the same vulnerability are present in other languages. For example, when using Golang's net/http/cgi module, and deploying as a CGI application. This indicates the vulnerability is a standard danger in CGI environments. It is problematic that it remains a danger in modern PHP environments.

## What is affected?

Private application code can be affected, and is the hardest to fix:

In your own PHP code, if you trust the content of getenv('HTTP_*') or $_SERVER['HTTP_*'] as if it were an environment
variable (while processing a request), you are vulnerable to a client modifying that data.

But even if you don't do this in your own code, your application may be vulnerable by using libraries that do this:

* If you use Guzzle, with any version past the early release candidates for 4.0.0 (right through to 6), and you send a request, using the Client class, while processing a request, then you are vulnerable
* If you use any project that internally uses such a Guzzle client, and it makes such a request, then you're also vulnerable
    * e.g. Drupal vulnerabilities due to usage of Guzzle in web requests
    * e.g. more recent versions of the AWS SDK for PHP

* Go's net/http will trust HTTP_PROXY in environment variables
* Python's requests module will trust HTTP_PROXY in environment variables

Guzzle is where we first found the vulnerability, but we suspect there are many, many other instances of libraries
trusting getenv('HTTP_PROXY') in a CGI environment.

In some cases, vulnerabilities are created by using code intended for a CLI context, while processing an HTTP request.
 For example, if you use Composer as a library, and it invokes its StreamContextFactory to make an HTTP request, and it
 does so as a subrequest from another, normal request, that is vulnerable, and Composer's HTTP requests could be snooped
 on or MitM'd. ("As a library", or in many cases, by wholesale copying of that Factory class out of Composer to other
 applications; ironic given Composer's purpose)

## Prevention

### Summary

* If you can avoid it, do not deploy into environments where the CGI data is merged into the actual environment variables
* Use and expect `CGI_HTTP_PROXY` to set the proxy for a CGI application's internal requests, if necessary
    * You can still support `HTTP_PROXY`, but you must assert that CGI is not in use
    * In PHP, check `PHP_SAPI == 'cli'`
    * Otherwise, a simple check is to not trust `HTTP_PROXY` if `REQUEST_METHOD` is also set (RFC 3875 seems to require this meta-variable: "The REQUEST_METHOD meta-variable MUST be set to the method which should be used by the script to process the request")

To put it plainly: there is no way to trust the value of an HTTP_ env var in a CGI environment. They cannot be distinguished from request headers, in any way. So, any usage of HTTP_PROXY in a CGI context is suspicious.

If you need to configure the proxy of a CGI application via an environment variable, use a variable name that will not conflict with request headers. That is: one that does not begin with HTTP_. We strongly recommend you go for CGI_HTTP_PROXY.

#### PHP

CLI-only code may safely trust `$_SERVER['HTTP_PROXY']` or `getenv('HTTP_PROXY')`. But bear in mind that code written
for the CLI context often ends up running in a SAPI eventually, particularly utility or library code. And, with open
source code, that might not even be your doing. So, if you are going to rely on HTTP_PROXY at all, you should guard that
code with a check of the `PHP_SAPI` constant.

## Immediate Mitigation

The best immediate mitigation without patching libraries is to block Proxy request headers upstream. How you do so depends on your web or CGI server:

### Nginx/FastCGI

In this configuration, PHP is vulnerable, for example. Use this to block the header from being passed on to PHP-FPM, PHP-PM etc.

```
fastcgi_param HTTP_PROXY "";
```

### Apache/CGI

In this configuration, any language may be vulnerable (the `HTTP_PROXY` env var is "real").

If you are using mod_headers, you can unset the Proxy header with this directive:

```
RequestHeader unset Proxy
```

If you are using mod_security, you can use a rule like (vary the action to taste):

```
SecRuleEngine On
SecRule &REQUEST_HEADERS:Proxy "@gt 0" "log,deny,msg:'httpoxy denied'"
```

### HAProxy

```
http-request deny if req.hdr_cnt(Proxy) gt 0
```

### IIS/FastCGI component for IIS 6.0 and IIS 7.0

```
[...]
```

### Ineffective fixes

These don't work. Don't even bother:

#### PHP

* Using `unset($_SERVER['HTTP_PROXY'])` does not affect the value returned from getenv(), so is not an effective mitigation
* Using `putenv('HTTP_PROXY=')` does not work either (to be precise: it only works if that value is coming from an actual environment variable rather than a header - so, it cannot be used for mitigation)

## What is not affected

* Python deployed using wsgi separates the request header `HTTP_*` environ from `os.environ`, so applications can make
  clever decisions about which to trust
* Go's `net/http/fcgi` is not affected (does not put CGI data in actual env vars)

## Timeline

Fill from disclosure document

## References

* https://secure.php.net/getenv
* http://php.net/manual/en/function.getenv.php
* http://www.faqs.org/rfcs/rfc3875.html - 4.1.18. Protocol-Specific Meta-Variables
* https://forum.nginx.org/read.php?2,244407,244485#msg-244485
* https://www.nginx.com/resources/wiki/start/topics/examples/phpfcgi/
* http://ruby-doc.org/stdlib-2.3.1/libdoc/uri/rdoc/URI/Generic.html#method-i-find_proxy last paragraph
