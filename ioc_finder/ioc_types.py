"""IOC type defs"""

from typing import Dict, List, Mapping, Union

from pymisp import MISPAttribute

IndicatorList = List[Union[str, MISPAttribute]]
IndicatorDict = Dict[str, IndicatorList]
IndicatorData = Mapping[str, Union[IndicatorList, IndicatorDict]]

DEFAULT_IOC_TYPES = [
    "asns",
    "attack_mitigations",
    "attack_tactics",
    "attack_techniques",
    "authentihashes",
    "bitcoin_addresses",
    "cves",
    "domains",
    "email_addresses",
    "email_addresses_complete",
    "file_paths",
    "google_adsense_publisher_ids",
    "google_analytics_tracker_ids",
    "imphashes",
    "ipv4_cidrs",
    "ipv4s",
    "ipv6s",
    "mac_addresses",
    "md5s",
    "monero_addresses",
    "registry_key_paths",
    "sha1s",
    "sha256s",
    "sha512s",
    "ssdeeps",
    "tlp_labels",
    "urls",
    "user_agents",
    "xmpp_addresses",
]
