---
layout: plain
---

## Yet Another Named Disclosure

We think it's worthwhile to give a name to a vulnerability that's broadly spread throughout an ecosystem (in this case PHP),
and poorly documented. Especially when its age shows it to be prone to reoccur.

httpoxy has existed (and been known about)
for a long time, yet new occurrences of the vulnerability were still being introduced as late as 2016. Indeed, we found a
large number of feature requests for HTTP clients to _add_ the ability to read `HTTP_PROXY` in Github issues.

Consider the fact that LWP, curl and Ruby teams all noticed at some point over the last 15
years, yet thousands of applications remain vulnerable today. We can only think that's because their finding wasn't
loudly and urgently transmitted to everyone else using CGI. So, we think this calls for a slightly "louder" fix.

## Disclosure Research Team

##### Vend
* Dominic Scheirlinck
* Richard Rowe
* Morgan Pyne
* Scott Geary

##### Red Hat Product Security
* Kurt Seifried

Thanks to everyone else who had suggestions and helped us prepare this site.

## Licensing

<div class="row">
    <div class="col-sm-9">
        <p xmlns:dct="http://purl.org/dc/terms/">
            To the extent possible under law, <a rel="dct:publisher" href="https://httpoxy.org/"><span property="dct:title">Dominic
            Scheirlinck</span> and <span property="dct:title">Vend Limited</span></a> have waived all copyright and related or
            neighboring rights to <span property="dct:title">the httpoxy disclosure page (and logo)</span>. (aka <abbr>CCO</abbr>).
        </p>
        <p>
            This means you can use the logo without attribution if you'd like, and you don't need to ask for permission.
        </p>
        <p markdown="1">
            If you would like to give attribution, the logo was designed by [Nicola Horlor](http://www.nicolahorlor.com/)
            and the team at [Vend](https://www.vendhq.com/), an online retail point-of-sale company.
        </p>
    </div>
    <div class="col-sm-3">
        <a rel="license"
           href="http://creativecommons.org/publicdomain/zero/1.0/">
            <img src="https://licensebuttons.net/p/zero/1.0/88x31.png" style="border-style: none;" alt="CC0" />
        </a>
    </div>
</div>

## Contact

We are available for comment at [contact@httpoxy.org](mailto:contact@httpoxy.org?subject=Press), or
[@httpoxy](https://twitter.com/httpoxy) on Twitter.
