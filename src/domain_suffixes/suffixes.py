import logging
from typing import List, Optional

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

# from domain_suffixes.trie_structure import _Trie, PUNY_PREFIX

_logger = logging.getLogger(__name__)

# links to iana and icann sources for TLD / suffix information
TLD_LIST_URL = "https://www.iana.org/domains/root/db"
SUFFIX_LIST_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

# manually parse all IANA TLD pages and pulled registration dates. This takes quite a while to do
# so shipping this resource file with the source
tld_reg_date_resource = "tld_reg_dates_v1.txt"

ipv4_pattern = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
ipv6_pattern = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
# via MS Defender Blog Post
private_ipv4_pattern = re.compile(r'(^127\.)|(^10\.)|(^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.)|(^192\.168\.)')

PUNY_PREFIX = "xn--"

##############################
# Internal API
##############################


def is_puny_code(label):
    return label[:4] == PUNY_PREFIX


class _Node:
    """A node in the trie structure"""

    def __init__(self, label):
        # the suffix label for this node
        self.label = label

        # whether this label is the end of a suffix
        self.is_end = False

        # a dictionary of child labels
        self.children = {}

        self.is_tld = False
        self.is_suffix = False
        self.metadata = None

    def set_metadata(self, metadata):
        self.metadata = metadata
        if isinstance(metadata, _TLDInfo):
            self.is_tld = True
            self.is_suffix = False
        elif isinstance(metadata, _SuffixInfo):
            self.is_tld = False
            self.is_suffix = True
            self.is_end = True


class _Trie(object):
    """The trie object"""

    def __init__(self):
        self.root = _Node("")

    def insert(self, suffix, metadata=None, is_public_suffix=None):
        """Insert a suffix into the trie"""
        node = self.root
        tld_info = None

        # Loop through each label in suffix in reverse order
        labels = suffix.split(".")[::-1]
        for label in labels:
            found_node = node.children.get(label)
            if found_node:
                node = found_node
            else:
                new_node = _Node(label)
                node.children[label] = new_node
                node = new_node
            if tld_info is None:
                tld_info = node
        # add node metadata
        if is_public_suffix is not None:
            assert tld_info is not None
            assert metadata is None
            metadata = _SuffixInfo(suffix, is_public_suffix, tld_info.metadata)
        node.set_metadata(metadata)

    def get_node(self, labels):
        node = self.root
        labels = labels[::-1]
        for i, label in enumerate(labels):
            tmp = node.children.get(label)
            if tmp:
                node = tmp
        if node == self.root:
            return None
        return node

    def get_longest_sequence(self, fqdn, puny_suffixes):
        """
        Returns the longest trie sequence found in the trie tree
        """
        node = self.root
        labels = fqdn.split(".")
        rev_labels = labels[::-1]

        if is_puny_code(rev_labels[0]):
            # if puny code tld is passed in, turn it to unicode and look it up
            rev_labels[0] = puny_suffixes[rev_labels[0]]

        for i, label in enumerate(rev_labels):
            if label in node.children:
                node = node.children[label]
            else:
                break
        if node:
            return node.metadata, labels[:-i]
        return None


@dataclass
class _TLDInfo:
    """  """
    suffix: str
    puny: str
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


##############################
# Public API
##############################


@dataclass
class ParsedResult:
    """
    tld: the actual top level domain
    effective_tld: the full public (or private) suffix, which may consist of multiple labels
    registrable_domain: domain name plus the effective TLD. Essentially the thing a person purchases from a Registrar
    registrable_domain_host: the domain name without the effective TLD
    fqdn: fully qualified domain name
    pqdn: partially qualified domain name: all the stuff to the left of the registrable domain
    """
    tld: str
    tld_puny: str
    tld_type: str
    tld_registry: str
    tld_create_date: str
    effective_tld: str
    effective_tld_is_public: bool
    host_labels: List[str]
    ipv4: bool = False
    ipv6: bool = False

    @property
    def registrable_domain(self) -> Optional[str]:
        if self.is_fqdn:
            return f"{self.host_labels[-1]}.{self.effective_tld}"
        return None

    @property
    def registrable_domain_host(self) -> Optional[str]:
        if self.is_fqdn:
            return self.host_labels[-1]
        return None

    @property
    def fqdn(self) -> str:
        if self.is_fqdn:
            return f"{'.'.join(self.host_labels)}.{self.effective_tld}"
        # just return the IP address
        return self.host_labels[0]

    @property
    def pqdn(self) -> Optional[str]:
        if self.is_fqdn:
            return '.'.join(self.host_labels[:-1])
        return None

    @property
    def pqdn_labels(self) -> Optional[List[str]]:
        if self.is_fqdn:
            return self.host_labels[:-1]
        return None

    @property
    def is_fqdn(self) -> bool:
        return not self.is_ip

    @property
    def is_ip(self) -> bool:
        return self.ipv4 or self.ipv6

    @property
    def is_tld_multi_part(self) -> bool:
        return self.tld != self.effective_tld

    @property
    def is_punycode(self) -> bool:
        return self.tld_puny is not None

    def ascii_ify_tld(self) -> str:
        if self.is_punycode:
            return self.ascii_ify_puny(self.tld_puny)
        return self.tld

    @staticmethod
    def ascii_ify_puny(self, puny_host) -> str:
        unicode_host = idna.decode(puny_host)
        return ParsedResult.ascii_ify_unicode(unicode_host)

    @staticmethod
    def ascii_ify_unicode(unicode_host) -> str:
        ascii_host = unidecode(unicode_host)
        return ascii_host

    def is_ipv4_private(self) -> Optional[bool]:
        if self.ipv4:
            return private_ipv4_pattern.match(self.fqdn) is not None
        return None


class Suffixes:
    def __init__(self, read_cache=True, save_cache=True, cache_path="suffix_data.cache"):
        if read_cache and cache_path and os.path.exists(cache_path):
            _logger.info("loading suffix data from cache")
            with open(cache_path, 'rb') as handle:
                suffix_trie, puny_suffixes = pickle.load(handle)
            self._suffix_trie = suffix_trie
            self._puny_suffixes = puny_suffixes
        else:
            _logger.info("manually collecting and parsing domain suffix data")
            tld_create_dates = self.load_tld_create_dates()
            self._suffix_trie = self.load_all_tlds(tld_create_dates)
            self.load_manual_tlds()
            # create a punycode suffix reverse index
            self._puny_suffixes = {}
            root_tlds = self._suffix_trie.root.children
            for tld in root_tlds:
                tld_node = root_tlds[tld].metadata
                if tld_node.puny:
                    self._puny_suffixes[tld_node.puny] = tld_node.suffix
            # self.enrich_gtlds()
            self.enrich_tld_suffixes()

            if save_cache and cache_path:
                _logger.info("saving domain suffix data to cache")
                with open(cache_path, 'wb') as handle:
                    pickle.dump((self._suffix_trie, self._puny_suffixes), handle)

    @staticmethod
    def load_tld_create_dates():
        """
        This resource file was created by parsing the individual IANA TLD pages. This takes way to long
        to do every time the TLD data cache is being rebuilt (and I don't want to piss IANA off), so
        I'm running this periodically and will update the source as new TLDs are created.
        """
        with open(tld_reg_date_resource, 'r') as handle:
            lines = handle.readlines()
        tld_create_dates = {}
        for line in lines:
            parts = line.strip().split(",")
            tld_create_dates[parts[0]] = datetime.strptime(parts[1], '%Y-%m-%d').date()
        return tld_create_dates

    @staticmethod
    def load_all_tlds(tld_reg_dates):
        """
        Load all known TLDs from iana. The html page has the TLD
        type and the registry information so I have to parse the html to get the info.
        Yup, totally know this is brittle.
        """
        trie = _Trie()
        revoked_tld = "Not assigned"
        # regex for the IANA URL for idn TLDs
        PUNY_TLD_PATTERN = "^\/domains\/root\/db\/xn--(.+?)\.html"
        response = requests.get(TLD_LIST_URL)
        if response.status_code != 200:
            raise Exception(f"{TLD_LIST_URL} error {response.status_code}")

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
            # this is brittle, but parsing out the right to left and L2R unicode chars
            tld = link.text.replace(".", "").replace('‏', '').replace('‎', '')
            # parse the TLD type
            tld_type = data[1].text
            # parse the TLD registry
            registry = data[2].text
            # only collect active TLDs
            if registry != revoked_tld:
                # check for punycode TLD (starts with xn--)
                delegation_link = link["href"]
                puny_tld = re.search(PUNY_TLD_PATTERN, delegation_link)
                if puny_tld:
                    puny_tld = PUNY_PREFIX + puny_tld.group(1)
                # get the TLD registration date
                tld_reg_date = tld_reg_dates.get(tld)
                if tld_reg_date is None:
                    _logger.warning(f"Registration date not found for TLD '{tld}' ")
                # populate tld info
                trie.insert(tld, _TLDInfo(tld, puny_tld, tld_type, registry, tld_reg_date))
        return trie

    def load_manual_tlds(self):
        # add in the onion TLD manually
        tld = "onion"
        self._suffix_trie.insert(tld,
            _TLDInfo(tld, None, "host_suffix", "Tor", "2015-09-15"))

    def enrich_tld_suffixes(self):
        """
        Pull in all known public suffixes
        TODO: A lot of these are know considered multi label TLDs, like "co.uk", but instead are suffixes used
              by dynamic DNS providers. I need to figure out a way to differentiate the two and add dynamic dns
              as extra metadata on a suffix.
        """
        response = requests.get(SUFFIX_LIST_URL)
        if response.status_code != 200:
            raise Exception(f"{SUFFIX_LIST_URL} error {response.status_code}")
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
                    self._suffix_trie.insert(suffix, _TLDInfo(suffix, puny, "country-code", None, None))

    # def tld_types(self, counts=False):
    #     """ Return either the distinct set of TLD types or the count of distinct TLD types"""
    #     tld_types = [self._suffixes[tld]["type"] for tld in self._suffixes]
    #     tld_type_set = set(tld_types)
    #     if counts:
    #         return {tld_type: tld_types.count(tld_type) for tld_type in tld_type_set}
    #     else:
    #         return tld_type_set

    def get_all_tlds(self):
        """ Just return the effective TLD for the FQDN """
        tlds = [node for node in self._suffix_trie.root.children]
        return tlds

    def get_tld(self, fqdn):
        """ Just return the effective TLD for the FQDN """
        node, _ = self._suffix_trie.get_longest_sequence(fqdn, self._puny_suffixes)
        if node:
            return node.suffix
        return None

    def parse(self, fqdn, skip_ip_check=False, skip_protocol_check=True):
        if not skip_ip_check:
            if ipv4_pattern.match(fqdn):
                return self._ip_result(fqdn, True)
            if ipv6_pattern.match(fqdn):
                return self._ip_result(fqdn, False)

        # check for protocol prefix
        if skip_protocol_check is False and "://" in fqdn:
            print("doing check")
            index = fqdn.index("://")
            fqdn = fqdn[index + 3:]

        node, host_labels = self._suffix_trie.get_longest_sequence(fqdn, self._puny_suffixes)
        if not node:
            return None
        if isinstance(node, _TLDInfo):
            return ParsedResult(
                node.suffix,
                node.puny,
                node.tld_type,
                node.registry,
                node.create_date,
                node.suffix,
                True,
                host_labels)
        elif isinstance(node, _SuffixInfo):
            return ParsedResult(
                node.root_suffix.suffix,
                node.root_suffix.puny,
                node.root_suffix.tld_type,
                node.root_suffix.registry,
                node.root_suffix.create_date,
                node.suffix,
                node.is_public,
                host_labels)
        else:
            raise Exception("Invalid type")

    @staticmethod
    def _ip_result(ip, is_ipv4):
        return ParsedResult(None, None, None, None, None, None, None, [ip], is_ipv4, not is_ipv4)


def run_test():
    fqdn = "65.22.218.1"
    result = Suffixes(read_cache=True).parse(fqdn)
    rd = result.registrable_domain
    print(rd)


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
