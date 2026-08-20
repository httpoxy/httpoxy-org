# TODO

## Retire the auxiliary domains (decided 2026-08-21)

Only `httpoxy.org` is kept. Both auxiliary domains are being dropped:

- **`httpoxy.com`** - expired 2026-07-04 and entered `redemptionPeriod` on 2026-08-15.
  Namecheap's restore fee (~USD $100) was judged not worth paying. It served an S3
  `RedirectAllRequestsTo` 301 to `httpoxy.org` behind CloudFront; that redirect is
  already dead and the name will drop around mid-September 2026.
- **`httpo.xyz`** - auto-renew off, lapses 2027-07-04. Never used: zero Internet
  Archive snapshots in its lifetime, no references in public code, no site, no
  infrastructure beyond a registrar parking page.

Consequences to be aware of:

- Anyone typing `httpoxy.com` after the drop reaches whoever registers it next, not
  this site. That is a real risk for a disclosure page (third-party nginx configs in
  the wild carry comments reading `# mitigate httpoxy.com`), and it was the argument
  for redeeming it. The cost was judged higher than the risk.
- The AWS resources behind the `.com` redirect (Route 53 zone, `site.httpoxy-com`
  bucket, CloudFront distribution, ACM certificate) are declared in the private
  `dominics/tf-config` repo under `aws/dns/httpoxy/` via the `site-redirect` module.
  They need removing there, not here.
- `httpoxy.org` itself is unaffected. Its registration moves from Namecheap to
  Porkbun; DNS stays on Route 53 throughout.
