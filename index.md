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
<strong>httpoxy</strong> is a set of vulnerabilities affecting code running in CGI or CGI-like environments. In essence,
it boils down to a namespace conflict:
</p>

* RFC 3875 (CGI) puts the HTTP 'Proxy' header from a request into the environment as HTTP_PROXY
* HTTP_PROXY is a popular environment variable used to configure an outgoing proxy

If an HTTP client, running in a server side process, makes an outgoing connection to an internal API like
so:

```php
<?php
    $proxy = getenv('HTTP_PROXY');
?>
```
