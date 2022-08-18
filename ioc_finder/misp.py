"""Module to convert ioc to MISPAttributes"""

import pymisp


def create_tag(value):
    """Creates a MISP tag"""
    tag = pymisp.MISPTag()
    tag.value = value
    return tag


def create_attribute(misp_category, misp_type, value):
    """Creates a MISP attribute"""
    attribute = pymisp.MISPAttribute()
    attribute.distribution = 0
    attribute.category = misp_category
    attribute.type = misp_type
    attribute.value = value
    return attribute


def convert2misp(misp_cls, *args):
    """converts a value to MISP object"""
    misp_object = None
    if misp_cls == "attribute":
        misp_object = create_attribute(*args)
    if misp_cls == "tag":
        misp_object = create_tag(*args)
    return misp_object


MISP_MAPPER = {
    "asns": ["attribute", "Network activity", "AS"],
    "authentihashes": ["attribute", "Payload delivery", "authentihash"],
    "bitcoin_addresses": ["attribute", "Financial fraud", "btc"],
    "cves": ["attribute", "External analysis", "vulnerability"],
    "domains": ["attribute", "Network activity", "domain"],
    "email_addresses": ["attribute", "Network activity", "email"],
    "email_addresses_complete": ["attribute", "Network activity", "email"],
    "file_paths": ["attribute", "Payload delivery", "filename"],
    "imphashes": ["attribute", "Payload delivery", "imphash"],
    "ipv4_cidrs": ["attribute", "Network activity", "domain|ip"],
    "ipv4s": ["attribute", "Network activity", "domain|ip"],
    "ipv6s": ["attribute", "Network activity", "domain|ip"],
    "mac_addresses": ["attribute", "Network activity", "mac-address"],
    "md5s": ["attribute", "Payload delivery", "md5"],
    "monero_addresses": ["attribute", "Financial fraud", "xmr"],
    "registry_key_paths": ["attribute", "Persistence mechanism", "regkey"],
    "sha1s": ["attribute", "Payload delivery", "sha1"],
    "sha256s": ["attribute", "Payload delivery", "sha256"],
    "sha512s": ["attribute", "Payload delivery", "sha512"],
    "ssdeeps": ["attribute", "Payload delivery", "ssdeep"],
    "tlp_labels": ["tag"],
    "urls": ["attribute", "Network activity", "url"],
    "user_agents": ["attribute", "Network activity", "user-agent"],
    "xmpp_addresses": ["attribute", "Social network", "jabber-id"],
}


def to_misp_attributes(ioc_type, values):
    """Converts a list of iocs with the same type into MISP objects"""
    if isinstance(values, list):
        return [
            convert2misp(*MISP_MAPPER[ioc_type], value)
            for value in values
            if ioc_type in MISP_MAPPER
        ]
    return values


def convert(iocs):
    """Converts IOC string values to MISP attributes and tag"""
    return {
        ioc_type: to_misp_attributes(ioc_type, values)
        for ioc_type, values in iocs.items()
    }
