import logging
import requests
from bs4 import BeautifulSoup
import re
import pickle
import os

_logger = logging.getLogger(__name__)

class TrieNode:
    """A node in the trie structure"""

    def __init__(self, label):
        # the suffix label for this node
        self.label = label

        # whether this label is the end of a suffix
        self.is_end = False

        # a dictionary of child labels
        self.children = {}


class Trie(object):
    """The trie object"""

    def __init__(self):
        self.root = TrieNode("")

    def insert(self, suffix):
        """Insert a suffix into the trie"""
        node = self.root

        # Loop through each label in suffix in reverse order
        labels = suffix.split(".")[::-1]
        for label in labels:
            if label in node.children:
                node = node.children[label]
            else:
                new_node = TrieNode(label)
                node.children[label] = new_node
                node = new_node

        # Mark the end of a suffix
        node.is_end = True

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
        return ".".join(labels[::-1][len(labels) - i:])


class Suffixes:
    # links to iana and icann sources for TLD / suffix information
    gTLDs_url = "https://www.icann.org/resources/registries/gtlds/v2/gtlds.json"
    tld_list_url = "https://www.iana.org/domains/root/db"
    suffix_list_url = "https://publicsuffix.org/list/public_suffix_list.dat"

    def __init__(self, read_cache=True, save_cache=True, cache_path="suffix_data.cache"):
        if read_cache and cache_path and os.path.exists(cache_path):
            _logger.info("loading suffix data from cache")
            with open(cache_path, 'rb') as handle:
                suffixes, puny_suffixes, suffix_trie = pickle.load(handle)
            self._suffixes = suffixes
            self._puny_suffixes = puny_suffixes
            self._suffix_trie = suffix_trie
        else:
            _logger.info("manually collecting and parsing domain suffix data")
            self._suffixes = self.load_all_tlds()
            # create a punycode suffix reverse index
            self._puny_suffixes = {}
            for suffix in self._suffixes:
                puny_suffix = self._suffixes[suffix]["puny_suffix"]
                if puny_suffix:
                    self._puny_suffixes[puny_suffix] = suffix
            self.enrich_gtlds()
            self._suffix_trie = self.enrich_tld_suffixes()

            if save_cache and cache_path:
                _logger.info("saving domain suffix data to cache")
                with open(cache_path, 'wb') as handle:
                    pickle.dump((self._suffixes, self._puny_suffixes, self._suffix_trie), handle)

    def load_all_tlds(self):
        """
        Initialization Step 1: load all known TLDs from iana. The html page has the TLD
        type and the registry information so I have to parse the html to get the info.
        Yup, totally know this is brittle.
        """
        tlds = {}
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
                raise Exception("Row format change")
            # parse out tld and delegation record link
            link = data[0].find("a")
            delegation_link = delegation_link_prefix + link["href"]
            tld = link.text.replace(".", "")
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
                tlds[tld] = {}
                tlds[tld]["puny_suffix"] = puny_tld
                tlds[tld]["delegation_record"] = delegation_link
                tlds[tld]["type"] = tld_type
                tlds[tld]["registry"] = registry
        return tlds

    def enrich_gtlds(self):
        """
        Initialization Step 2: get extra information about gTLDs, most notably the date the TLD was created
        """
        # enrich gTLDs with extra context
        response = requests.get(self.gTLDs_url)
        if response.status_code != 200:
            raise Exception(f"{self.gTLDs_url} error {response.status_code}")
        gtlds = response.json()
        gtld_updated = gtlds["updatedOn"]
        gtld_version = gtlds["version"]
        for gtld in gtlds["gTLDs"]:
            if gtld["applicationId"] is not None:
                # only pull in active gTLDs
                tld = gtld["gTLD"]
                # check for puny tld
                if tld[:4] == "xn--":
                    tld = self._puny_suffixes[tld]
                # make sure we know about this TLD
                if tld not in self._suffixes:
                    raise Exception(f"{tld} not in list of known TLDs")
                # if the two registry values are different, add the icann value in parins
                # - parses out punctuation and lower cases to check match
                if re.sub(r'[^\w\s]', '', self._suffixes[tld]['registry'].lower()) != re.sub(r'[^\w\s]', '', gtld[
                    "registryOperator"].lower()):
                    self._suffixes[tld]['registry'] = f"{self._suffixes[tld]['registry']} ({gtld['registryOperator']})"
                self._suffixes[tld]["start_date"] = gtld["delegationDate"]

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

        # filter out blank lines and comments
        suffix_list = list(filter(lambda line: len(line) > 0 and line[:3] != "// ", suffix_list))

        # add each sub suffix to it's parent TLD
        trie = Trie()
        for suffix in suffix_list:
            suffix = suffix.strip()
            # strip out wildcards
            if suffix[:2] == "*." or suffix[:2] == "!.":
                suffix = suffix[2:]
            if "." in suffix:
                # check for puny tld
                tld = suffix[suffix.rindex(".") + 1:]
                if tld in self._puny_suffixes:
                    suffix = suffix.replace(tld, self._puny_suffixes[tld])
                # add suffix to trie tree
                trie.insert(suffix)
        return trie

    def tld_types(self, counts=False):
        """ Return either the distinct set of TLD types or the count of distinct TLD types"""
        tld_types = [self._suffixes[tld]["type"] for tld in self._suffixes]
        tld_type_set = set(tld_types)
        if counts:
            return {tld_type: tld_types.count(tld_type) for tld_type in tld_type_set}
        else:
            return tld_type_set

    def get_tld(self, fqdn):
        suffix = self._suffix_trie.get_longest_sequence(fqdn)
        if len(suffix) == 0:
            suffix = None
        return suffix


