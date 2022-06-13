from domain_suffixes.suffixes import _TLDInfo, _SuffixInfo

PUNY_PREFIX = "xn--"


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

