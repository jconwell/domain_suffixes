import logging
import requests
from bs4 import BeautifulSoup
import re
import pickle
import os
from dataclasses import dataclass


_logger = logging.getLogger(__name__)


@dataclass
class TLDInfo:
    """  """
    suffix: str
    puny: str
    delegation_link: str
    tld_type: str
    registry: str
    create_date: str


@dataclass
class SuffixInfo:
    """  """
    suffix: str
    is_public: bool
    root_suffix: object
    # is_dynamic_dns


# FQDNResult = namedtuple("FQDNResult", "sub_domain registered_domain TLDInfo")


class Node:
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
        if isinstance(metadata, TLDInfo):
            self.is_tld = True
            self.is_suffix = False
        elif isinstance(metadata, SuffixInfo):
            self.is_tld = False
            self.is_suffix = True
            self.is_end = True


class Trie(object):
    """The trie object"""

    def __init__(self):
        self.root = Node("")

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
                new_node = Node(label)
                node.children[label] = new_node
                node = new_node
            if tld_info is None:
                tld_info = node
        # add node metadata
        if is_public_suffix is not None:
            assert tld_info is not None
            assert metadata is None
            metadata = SuffixInfo(suffix, is_public_suffix, tld_info.metadata)
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

    def get_longest_sequence(self, fqdn):
        """
        Returns the longest trie sequence found in the trie tree
        """
        node = self.root
        labels = fqdn.split(".")[::-1]
        for i, label in enumerate(labels):
            if label in node.children:
                node = node.children[label]
            else:
                break
        # reverse the labels back, then slice the labels found in the trie
        # return labels[::-1][len(labels) - i:]
        if node:
            return node.metadata
        return None


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
                    self._puny_suffixes[tld_node.puny] = tld_node.tld
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
        import urllib.parse

        # tlds = {}
        trie = Trie()

        delegation_link_prefix = "https://www.iana.org"
        revoked_tld = "Not assigned"
        PUNY_PATTERN = "^https:\/\/www\.iana\.org\/domains\/root\/db\/xn--(.+?)\.html"

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
                puny_tld = re.search(PUNY_PATTERN, delegation_link)
                if puny_tld:
                    puny_tld = "xn--" + puny_tld.group(1)
                # populate tld info
                trie.insert(
                    tld,
                    TLDInfo(tld, puny_tld, delegation_link, tld_type, registry, None)
                )
        return trie

    def load_manual_tlds(self):
        # add in the onion TLD manually
        tld = "onion"
        self._suffix_trie.insert(
            tld,
            TLDInfo(tld, None, "https://datatracker.ietf.org/doc/html/rfc7686", "host_sufix", "Tor", "2015-09-15")
        )

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
                tld_node.create_date = gtld["delegationDate"]

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
                    if "// xn--" in previous_line:
                        puny = previous_line[3:]
                        puny = puny[:puny.index(" ")]
                    self._suffix_trie.insert(
                        suffix,
                        TLDInfo(suffix, puny, None, "country-code", None, None)
                    )

    def tld_types(self, counts=False):
        """ Return either the distinct set of TLD types or the count of distinct TLD types"""
        tld_types = [self._suffixes[tld]["type"] for tld in self._suffixes]
        tld_type_set = set(tld_types)
        if counts:
            return {tld_type: tld_types.count(tld_type) for tld_type in tld_type_set}
        else:
            return tld_type_set

    def get_tld(self, fqdn):
        suffix_node = self._suffix_trie.get_longest_sequence(fqdn)
        if suffix_node:
            return suffix_node.suffix
        return None


def main():
    suffixes = Suffixes()  # read_cache=False
    ret = suffixes.get_tld("stuff.co.uk")
    print(ret)


if __name__ == "__main__":
    main()
