
===============
Domain Suffixes
===============

*Note: the API is still being fleshed out and subject to change*

----
Goal
----

Domain Suffixes is a library for parsing Fully Qualified Domain Names (FQDNs) into their component parts,
as well as providing additional contextual information about TLDs, multi-label domain suffixes such as
:code:`.co.uk`, and known private multi-label suffixes, such as :code:`.duckdns.org`.

- TLD data came from parsing the `IANA Root Zone Database <https://www.iana.org/domains/root/db>`_
- Multi-label suffix data came from parsing the `Mozilla Public Suffix List <https://publicsuffix.org/list/public_suffix_list.dat>`_

The library also parses out the "second level domain" and all sub-domains in an FQDN.

----
Terminology
----

Coming up with a consistent naming convention for each specific part of a FQDN can get a little inconsistent and confusing.
For example :code:`somedomain.co.jp`: many people would say the second level domain (SLD) is :code:`somedomain`,
but actually the `2nd` level domain is :code:`.co` and `somedomain` is the `3rd` level domain.

Because of this the library uses a different naming convention in order to be explicitly clear and accurate.

    :code:`tld` - the actual top level domain of the FQDN. This is the domain that is controlled by IANA.

    :code:`effective_tld` - this is the full domain suffix which can be made up of 1 to many labels. The effective
    TLD is the thing a person chooses to register a domain under and is controlled by a Registrar, or in the case of
    private domain suffixes the company that owns the private suffix (like DuckDNS).

    :code:`registrable_domain` - this is the full domain name that a person registers with a Registrar and includes the
    effective tld.

    :code:`registrable_domain_host` - this is the label of the registrable domain without the effective tld. Most people
    call this the second level domain, but as you can see this can get confusing.

    :code:`pqdn` (Partially Qualified Domain Name) - this is the  list of sub-domains not including the registrable
    domain and the effective TLD.

    :code:`fqdn` (Fully Qualified Domain Name) - this is the full list of labels.

To give an example take the FQDN :code:`test.integration.api.somedomain.co.jp`

    :code:`tld` - jp

    :code:`effective_tld` - co.jp

    :code:`registrable_domain` - somedomain.co.jp

    :code:`registrable_domain_host` - somedomain

    :code:`pqdn` - test.integration.api

    :code:`fqdn` - test.integration.api.somedomain.co.jp

----
How Is This Different Than `tldextract <https://github.com/john-kurkowski/tldextract>`_ ?
----

tldextract is a great library if all you need is to parse out the TLD, or longest public domain suffix from a FQDN.

I wrote this library to pull in a bit more contextual metadata about each TLD/suffix to use mostly as features in
machine learning projects, such as:

- International TLDs in both unicode and puny code format
- The TLD type: generic, generic-restricted, country-code, sponsored, test, infrastructure, and host_suffix (.onion)
- The date the TLD was created
- In the case of multi-label effective TLDs, if it is public (owned by a Registrar) or private (owned by a private company)
- If the TLD (or any label in the FQDN) is puny code encoded, the ascii'ification of the unicode. This can be
useful for identifying registrable domains that using unicode characters that are very similar to the ascii
character used by legitimate domains, a common phishing technique.

----
TO DO List
----

1. A lot of the suffixes listed in https://publicsuffix.org/list/public_suffix_list.dat are not actually
recognized TLDs, but are suffixes used for Dynamic DNS (https://en.wikipedia.org/wiki/Dynamic_DNS).
At some point I'd like parse that information and to pull out Dynamic DNS suffixes from actual TLDs.

2. Probably more unit tests


