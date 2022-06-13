import logging
import requests
from datetime import datetime
from bs4 import BeautifulSoup
import re
import pickle
import os
from dataclasses import dataclass
import idna
from unidecode import unidecode

__author__ = "John Conwell"
__copyright__ = "John Conwell"
__license__ = "MIT"

from domain_suffixes.trie_structure import _Trie, PUNY_PREFIX

_logger = logging.getLogger(__name__)

ipv4_pattern = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
ipv6_pattern = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
# via MS Defender Blog Post
private_ipv4_pattern = re.compile(r'(^127\.)|(^10\.)|(^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.)|(^192\.168\.)')


@dataclass
class ParsedResult:
    """
    tld: the actual top level domain
    effective_tld: the full public (or private) suffix, which may consist of multiple labels
    registrable_domain: the domain name plus the effective TLD. Essentially the thing a person purchases from a Registrar
    registrable_domain_host: the domain name without the effective TLD
    fqdn: fully qualified domain name
    pqdn: partially qualified domain name: all the stuff to the left of the registrable domain
    """
    tld: str
    tld_puny: str
    tld_delegation_link: str
    tld_type: str
    tld_registry: str
    tld_create_date: str
    effective_tld: str
    effective_tld_is_public: bool
    registrable_domain: str
    registrable_domain_host: str
    fqdn: str
    pqdn: str
    ipv4: bool = False
    ipv6: bool = False

    def is_tld_multi_part(self):
        return self.tld != self.effective_tld

    def is_punycode(self):
        return self.tld_puny

    def ascii_ify_tld(self):
        if self.is_punycode():
            self.ascii_ify_puny(self.tld_puny)

    def ascii_ify_puny(self, puny_host):
        # puny_domain = "xn--crdit-agricole-ckb.xn--scurvrification-bnbe.com"
        # print(puny_domain)
        unicode_host = idna.decode(puny_host)
        # print(unicode_domain)
        return self.ascii_ify_unicode(unicode_host)

    def ascii_ify_unicode(self, unicode_host):
        ascii_host = unidecode(unicode_host)
        return ascii_host

    def is_ipv4_private(self):
        if self.ipv4:
            return private_ipv4_pattern.match(self.fqdn) is not None
        return None


@dataclass
class _TLDInfo:
    """  """
    suffix: str
    puny: str
    delegation_link: str
    tld_type: str
    registry: str
    create_date: str


@dataclass
class _SuffixInfo:
    """  """
    suffix: str
    is_public: bool
    root_suffix: object
    # is_dynamic_dns


class Suffixes:
    # links to iana and icann sources for TLD / suffix information
    tld_list_url = "https://www.iana.org/domains/root/db"
    gTLDs_url = "https://www.icann.org/resources/registries/gtlds/v2/gtlds.json"
    suffix_list_url = "https://publicsuffix.org/list/public_suffix_list.dat"

    def __init__(self, read_cache=True, save_cache=True, cache_path="suffix_data.cache"):
        if read_cache and cache_path and os.path.exists(cache_path):
            _logger.info("loading suffix data from cache")
            with open(cache_path, 'rb') as handle:
                suffix_trie, puny_suffixes  = pickle.load(handle)
            self._suffix_trie = suffix_trie
            self._puny_suffixes = puny_suffixes
        else:
            _logger.info("manually collecting and parsing domain suffix data")
            self._suffix_trie = self.load_all_tlds()
            self.load_manual_tlds()
            # create a punycode suffix reverse index
            self._puny_suffixes = {}
            root_tlds = self._suffix_trie.root.children
            for tld in root_tlds:
                tld_node = root_tlds[tld].metadata
                if tld_node.puny:
                    self._puny_suffixes[tld_node.puny] = tld_node.suffix
            self.enrich_gtlds()
            self.enrich_tld_suffixes()

            if save_cache and cache_path:
                _logger.info("saving domain suffix data to cache")
                with open(cache_path, 'wb') as handle:
                    pickle.dump((self._suffix_trie, self._puny_suffixes), handle)

    def load_all_tlds(self):
        """
        Initialization Step 1: load all known TLDs from iana. The html page has the TLD
        type and the registry information so I have to parse the html to get the info.
        Yup, totally know this is brittle.
        """
        trie = _Trie()
        delegation_link_prefix = "https://www.iana.org"
        revoked_tld = "Not assigned"
        # regex for the IANA URL for idn TLDs
        PUNY_TLD_PATTERN = "^https:\/\/www\.iana\.org\/domains\/root\/db\/xn--(.+?)\.html"
        response = requests.get(self.tld_list_url)
        if response.status_code != 200:
            raise Exception(f"{self.tld_list_url} error {response.status_code}")

        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table", class_="iana-table", id="tld-table")
        table = table.find("tbody")
        tld_rows = table.find_all("tr")
        for tld_row in tld_rows:
            data = tld_row.find_all("td")
            if len(data) != 3:
                raise Exception("IANA tld html format changed")
            # parse out tld and delegation record link
            link = data[0].find("a")
            delegation_link = delegation_link_prefix + link["href"]
            # this is brittle, but parsing out the right to left and L2R unicode chars
            tld = link.text.replace(".", "").replace('‏', '').replace('‎', '')
            # parse the TLD type
            tld_type = data[1].text
            # parse the TLD registry
            registry = data[2].text
            # only collect active TLDs
            if registry != revoked_tld:
                # check for punycode TLD (starts with xn--)
                puny_tld = re.search(PUNY_TLD_PATTERN, delegation_link)
                if puny_tld:
                    puny_tld = PUNY_PREFIX + puny_tld.group(1)
                # populate tld info
                trie.insert(tld, _TLDInfo(tld, puny_tld, delegation_link, tld_type, registry, None))
        return trie

    def load_manual_tlds(self):
        # add in the onion TLD manually
        tld = "onion"
        self._suffix_trie.insert(tld,
            _TLDInfo(tld, None, "https://datatracker.ietf.org/doc/html/rfc7686", "host_sufix", "Tor", "2015-09-15"))

    def enrich_gtlds(self):
        """
        Initialization Step 2: get extra information about gTLDs, most notably the date the TLD was created
        """
        # enrich gTLDs with extra context
        response = requests.get(self.gTLDs_url)
        if response.status_code != 200:
            raise Exception(f"{self.gTLDs_url} error {response.status_code}")
        gtlds = response.json()
        # gtld_updated = gtlds["updatedOn"]
        # gtld_version = gtlds["version"]
        for gtld in gtlds["gTLDs"]:
            if gtld["applicationId"] is not None:
                # only pull in active gTLDs
                tld = gtld["gTLD"]
                # check for puny tld
                if tld[:4] == "xn--":
                    tld = self._puny_suffixes[tld]
                # make sure we know about this TLD
                tld_node = self._suffix_trie.get_node([tld])
                if tld_node is None:
                    raise Exception(f"{tld} not in list of known TLDs")
                # if the two registry values are different, add the icann value in parins
                # - parses out punctuation and lower cases to check match
                tld_node = tld_node.metadata
                if (re.sub(r'[^\w\s]', '', tld_node.registry.lower()) !=
                        re.sub(r'[^\w\s]', '', gtld["registryOperator"].lower())):
                    tld_node.registry = f"{tld_node.registry} ({gtld['registryOperator']})"
                # parse the create date
                create_date = gtld["delegationDate"]
                if create_date:
                    create_date = datetime.strptime(create_date, '%Y-%m-%d').date()
                tld_node.create_date = create_date

    def enrich_tld_suffixes(self):
        """
        Initialization Step 3: pull in all known public suffixes
        TODO: A lot of these are know considered multi label TLDs, like "co.uk", but instead are suffixes used
              by dynamic DNS providers. I need to figure out a way to differentiate the two and add dynamic dns
              as extra metadata on a suffix.
        """
        response = requests.get(self.suffix_list_url)
        if response.status_code != 200:
            raise Exception(f"{self.suffix_list_url} error {response.status_code}")
        suffix_list = response.content.decode('utf-8')
        suffix_list = suffix_list.split("\n")

        # add each sub suffix to its parent TLD
        is_public_suffix = True
        for i, line in enumerate(suffix_list):
            if line == "// ===BEGIN PRIVATE DOMAINS===":
                is_public_suffix = False
            elif len(line) == 0 or line[:3] == "// ":
                # skip comments
                continue
            suffix = line.strip()
            # strip out wildcards
            if suffix[:2] == "*." or suffix[:2] == "!.":
                suffix = suffix[2:]
            if "." in suffix:
                # check for puny tld
                tld = suffix[suffix.rindex(".") + 1:]
                # add suffix to trie tree
                self._suffix_trie.insert(suffix, is_public_suffix=is_public_suffix)
            else:
                # There are 9 IDN TLDs in the suffix list that are NOT listed in the iana root zone database
                # - so adding them here (they are all country code IDN TLDs)
                if self._suffix_trie.get_node([suffix]) is None:
                    print(f"WARNING: {suffix} not in IANA root zone database. Adding to list of TLDs")
                    # parse out the puny code from the previous line if possible
                    previous_line = suffix_list[i - 1]
                    puny = None
                    if "// xn--" in previous_line:
                        puny = previous_line[3:]
                        puny = puny[:puny.index(" ")]
                    self._suffix_trie.insert(suffix, _TLDInfo(suffix, puny, None, "country-code", None, None))

    # def tld_types(self, counts=False):
    #     """ Return either the distinct set of TLD types or the count of distinct TLD types"""
    #     tld_types = [self._suffixes[tld]["type"] for tld in self._suffixes]
    #     tld_type_set = set(tld_types)
    #     if counts:
    #         return {tld_type: tld_types.count(tld_type) for tld_type in tld_type_set}
    #     else:
    #         return tld_type_set

    def get_tld(self, fqdn):
        """ Just return the effective TLD for the FQDN """
        node, _ = self._suffix_trie.get_longest_sequence(fqdn, self._puny_suffixes)
        if node:
            return node.suffix
        return None

    def parse(self, fqdn, skip_ip_check=False):
        if not skip_ip_check:
            if ipv4_pattern.match(fqdn):
                return self.ip_result(fqdn, True)
            if ipv6_pattern.match(fqdn):
                return self.ip_result(fqdn, False)

        node, labels = self._suffix_trie.get_longest_sequence(fqdn, self._puny_suffixes)
        if not node:
            return None
        if isinstance(node, _TLDInfo):
            return ParsedResult(
                node.suffix,
                node.puny,
                node.delegation_link,
                node.tld_type,
                node.registry,
                node.create_date,
                node.suffix,
                True,
                f"{labels[-1]}.{node.suffix}",
                labels[-1],
                f"{'.'.join(labels)}.{node.suffix}",
                '.'.join(labels[:-1]))
        elif isinstance(node, _SuffixInfo):
            return ParsedResult(
                node.root_suffix.suffix,
                node.root_suffix.puny,
                node.root_suffix.delegation_link,
                node.root_suffix.tld_type,
                node.root_suffix.registry,
                node.root_suffix.create_date,
                node.suffix,
                node.is_public,
                f"{labels[-1]}.{node.suffix}",
                labels[-1],
                f"{'.'.join(labels)}.{node.suffix}",
                '.'.join(labels[:-1]))
        else:
            raise Exception("Invalid type")

    def ip_result(self, ip, is_ipv4):
        ret = ParsedResult(None, None, None, None, None, None, None,None, None, None, ip, None)
        ret.ipv4 = is_ipv4
        ret.ipv6 = not is_ipv4
        return ret

def run_test():
    fqdn = "stuffandthings.com"
    result = Suffixes(read_cache=True).parse(fqdn)
    print(result)


def main():
    run_test()

    # suffixes = Suffixes(read_cache=True)  # read_cache=False
    # ret = suffixes.get_tld("stuff.xn--kput3i")
    # print(ret)

    # ret = suffixes.parse("costco.com")
    # ret = suffixes.parse("test.costco.api.someservice.tokyo.jp")
    # ret = suffixes.parse("costco.commmm")
    # print(ret)


if __name__ == "__main__":
    main()
