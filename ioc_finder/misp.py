"""Module to convert ioc to MISPAttributes"""

import pymisp


def create_tag(value):
    """Creates a MISP tag"""
    return pymisp.MISPTag(name=value)


def create_attribute(misp_category, misp_type, value):
    """Creates a MISP attribute"""
    attribute = pymisp.MISPAttribute()
    attribute.distribution = 0
    attribute.category = misp_category
    attribute.type = misp_type
    attribute.value = value
    return attribute


MISP_CONVERT_FUNCTIONS = {
    "attribute": create_attribute,
    "tag": create_tag,
}


def convert2misp(misp_type, *args):
    """converts a value to MISP object"""
    return MISP_CONVERT_FUNCTIONS[misp_type](*args)


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


def to_misp(ioc_type, values):
    """Converts a list of IoCs with the same type into MISP objects"""
    if isinstance(values, list) and ioc_type in MISP_MAPPER:
        return MISP_MAPPER[ioc_type][0], [
            convert2misp(*MISP_MAPPER[ioc_type], value)
            for value in values
        ]
    return None, []


def convert(iocs):
    """Converts IoCs to MISP attributes and tags"""
    misp_objects = {
        "attributes": [],
        "tags": [],
    }
    for ioc_type, values in iocs.items():
        misp_type, values = to_misp(ioc_type, values)
        if misp_type:
            misp_objects[f"{misp_type}s"] += values
    return misp_objects
