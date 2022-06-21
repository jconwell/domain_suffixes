
===============
domain_suffixes
===============

Note: *the public api is still being fleshed out and subject to change*

    Library for parsing out domain TLDs from FQDNs

`domain_suffixes` parses the TLD, or longest public suffix, from any fully qualified domain name (FQDN).

`domain_suffixes` downloads, parses, and merges the latest TLD and public domain suffix information from
the following IANA and ICANN resources:

- https://www.iana.org/domains/root/db
- https://publicsuffix.org/list/public_suffix_list.dat

----
How Is This Different Than `tldextract`?
----

If all you need is the TLD (or longest public domain suffix) parsed from a FQDN than tldextract will work
just fine for you. I wrote this library to pull a bit more metadata about each TLD/suffix to use mostly as
features in machine learning projects.

----
What Extra Metadata Is Included With TLDs?
----

- TLD name
- TLD type
 - sponsored, generic-restricted, generic, country-code, test, infrastructure
- TLD creation date
- TLD registry name
- TLD puny code

----
TODO
----
A lot of the suffixes listed in https://publicsuffix.org/list/public_suffix_list.dat are not actually
recognized TLDs, but are suffixes used for Dynamic DNS (https://en.wikipedia.org/wiki/Dynamic_DNS).
At some point I'd like parse that information and to pull out Dynamic DNS suffixes from actual TLDs.