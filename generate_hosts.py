import logging
import re
from logging.config import dictConfig
from pathlib import Path
from pytest import fail
from typing import Set
from urllib.request import urlretrieve


dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
            },
        },
        "loggers": {
            "bouncer": {
                "level": "INFO",
                "handlers": ["console"],
            }
        },
    }
)

HOSTS_URLS = {
    "adaway": "https://adaway.org/hosts.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/hostfile",
    "kad": (
        "https://raw.githubusercontent.com/FiltersHeroes/KADhosts"
        "/master/KADhosts.txt"
    ),
    "badd-boyz": (
        "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts"
        "/master/hosts"
    ),
    "coinblocker": "https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/hosts",
    "someonewhocares": "https://someonewhocares.org/hosts/hosts",
    "mvps": "https://winhelp2002.mvps.org/hosts.txt",
    "stevenblack": (
        "https://raw.githubusercontent.com/StevenBlack/hosts"
        "/master/data/StevenBlack/hosts"
    ),
}
SETTINGS_DIR = Path("settings/").resolve()
BUILD_DIR = Path("build/").resolve()
RETRIEVED_DIR = Path("retrieved/").resolve()
LOCAL_HOSTS_PATHS = [
    SETTINGS_DIR / "hphosts.ad_servers.hosts",
    SETTINGS_DIR / "to_block.domains",
]
WHITELIST_PATH = SETTINGS_DIR / "whitelist.domains"
HOSTS_BASE_PATH = SETTINGS_DIR / "hosts_base"
HOSTS_BUILD_PATH = BUILD_DIR / "hosts"
BLOCK_PREFIX = "127.0.0.1"
BLOCK_PREFIXES = {"0.0.0.0", "127.0.0.1"}
FILES_TO_IGNORE = {".DS_Store"}
HOSTS_DEPLOY_PATH = Path("/etc/hosts")
DELIMITER_TXT = "blocked by bouncer"

log = logging.getLogger("bouncer")


def generate() -> None:
    assert HOSTS_DEPLOY_PATH.exists()
    if BUILD_DIR.exists():
        assert BUILD_DIR.is_dir()
    else:
        BUILD_DIR.mkdir(parents=True, exist_ok=True)
    assert HOSTS_BASE_PATH.exists()
    assert WHITELIST_PATH.exists()

    domains = set()

    # Load the whitelist:
    with WHITELIST_PATH.open(mode="r") as file:
        whitelist = load_domains(file, is_hosts_file=False)

    # Retrieve and add domains from remote sources:
    if RETRIEVED_DIR.exists():
        assert RETRIEVED_DIR.is_dir()
        for path in RETRIEVED_DIR.iterdir():
            assert path.is_file()
            path.unlink()
    else:
        RETRIEVED_DIR.mkdir(parents=True, exist_ok=True)
    for id, url in HOSTS_URLS.items():
        path = RETRIEVED_DIR / f"{id}.hosts"
        rel_path = path.relative_to(Path(".").resolve())
        log.info(f"\n# Adding domains from '{rel_path}', retrieved from '{url}':")
        urlretrieve(url, path)
        with path.open(mode="rt") as file:
            add_domains(
                base=domains,
                new=load_domains(file, is_hosts_file=True, ignore=whitelist),
            )

    # Add domains from the files in `./settings/`:
    for path in Path("settings").iterdir():
        if path.is_file() and path.name not in FILES_TO_IGNORE:
            log.info(f"\n# Adding domains from '{path}':")
            with path.open(mode="rt") as file:
                add_domains(
                    base=domains,
                    new=load_domains(
                        file,
                        is_hosts_file=path.name.endswith(".hosts"),
                        ignore=whitelist,
                    ),
                )

    # Load the currently blocked domains:
    with HOSTS_DEPLOY_PATH.open(mode="r") as file:
        current = load_domains(file, is_hosts_file=True, ignore=whitelist)

    # Write the final hosts file:
    log.info(f"\n# Writing the final hosts file:")
    log.info(f"  - blocked domains: {len(domains)}")
    new_cnt = 0
    for domain in domains:
        if domain not in current:
            new_cnt += 1
    log.info(f"  - newly blocked: {new_cnt}\n")
    with HOSTS_BASE_PATH.open(mode="rt") as file:
        base_content = file.read()
    with HOSTS_BUILD_PATH.open(mode="wt") as file:
        file.write(base_content)
        file.write(f"\n\n#<{DELIMITER_TXT}>")
        for domain in sorted(domains):
            file.write(f"\n{BLOCK_PREFIX} " + domain)
        file.write(f"\n#</{DELIMITER_TXT}>\n")


def load_domains(
    file,
    *,
    is_hosts_file: bool,
    ignore: Set[str] = None,
) -> Set[str]:
    """The given file may be a hosts file or a domains file.

    A domains file contains one or more whitespace separated domains or IP-address.

    The files may contain comments following a #-character, which are ignored.

    :param file: The file from which to load domains.
    :param is_hosts_file: True when the given file is a hosts file.
    :param ignore: The domains or IP addresses to ignore.
    """
    if ignore is None:
        ignore = set()
    domains = set()
    last_ok_line = "-1"

    try:
        for line_idx, line in enumerate(file):
            last_ok_line = line_idx

            try:
                hash_idx = line.index("#")
            except ValueError:
                pass
            else:
                line = line[:hash_idx]

            if is_hosts_file:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] in BLOCK_PREFIXES:
                    for domain in parts[1:]:
                        if domain not in ignore:
                            domains.add(domain)
            else:
                for domain in line.strip().split():
                    domain = domain.strip()
                    if len(domain) > 0 and domain not in ignore:
                        domains.add(domain)

    except UnicodeDecodeError as err:
        log.fatal(f"last OK line: {last_ok_line}")
        raise err

    return domains


def add_domains(*, base: Set[str], new: Set[str]) -> None:
    """Add the new domains in the base set.

    :param base: The set in which to add the new domains.
    :param new: The new domains to add.
    """
    new_cnt = 0
    dup_cnt = 0
    for domain in new:
        if is_invalid_domain(domain):
            raise ValueError(f"Unexpected domain: '{domain}'")

        if domain in base:
            dup_cnt += 1
        else:
            base.add(domain)
            new_cnt += 1

    log.info(f" - added {new_cnt} domains")
    if dup_cnt > 0:
        log.info(f" - ignored {dup_cnt} duplicates")


IPV = r"([0-9]|[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"  # IP-address Value [0-255]
IPC = rf"\.{IPV}"  # IP-address Component: [0-255] with dot-prefix
IP_PATTERN = re.compile(rf"^{IPV}{IPC}{IPC}{IPC}$")
IP_LIKE_PATTERN = re.compile(r"^[\d.]+$")
PRIVATE_IP_REGEXES = [
    rf"0{IPC}{IPC}{IPC}",
    rf"10{IPC}{IPC}{IPC}",
    rf"100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7]){IPC}{IPC}",
    rf"127{IPC}{IPC}{IPC}",
    rf"169\.(1[6-9]|2[0-9]|3[0-1]){IPC}{IPC}",
    rf"192\.0\.[02]{IPC}",
    rf"192\.88\.99{IPC}",
    rf"192\.168{IPC}{IPC}",
    rf"198\.1[89]{IPC}{IPC}",
    rf"198\.51\.100{IPC}",
    rf"203\.0\.113{IPC}",
    rf"2(2[4-9]|3[0-9]){IPC}{IPC}{IPC}",
    rf"233\.252\.0{IPC}",
    rf"2(4[0-9]|5[0-5]){IPC}{IPC}{IPC}",
]
PRIVATE_IP_PATTERN = re.compile("^({})$".format("|".join(PRIVATE_IP_REGEXES)))


def is_invalid_domain(domain: str) -> bool:
    if IP_PATTERN.match(domain):
        return PRIVATE_IP_PATTERN.match(domain) is not None
    elif IP_LIKE_PATTERN.match(domain):
        return True
    else:
        return False


def test_invalid_domain_patterns():
    pattern = re.compile(f"^{IPV}$")
    assert pattern.match("0") is not None
    assert pattern.match("11") is not None
    assert pattern.match("256") is None
    assert pattern.match("512") is None

    pattern = re.compile(f"^{IPC}$")
    assert pattern.match(".0") is not None
    assert pattern.match(".255") is not None
    assert pattern.match(".256") is None
    assert pattern.match(".1.1") is None
    assert pattern.match("0.0.0.0") is None

    assert IP_PATTERN.match("0") is None
    assert IP_PATTERN.match("0.0.0") is None
    assert IP_PATTERN.match("0.0.0.0") is not None
    assert IP_PATTERN.match("255.255.0.0") is not None
    assert IP_PATTERN.match("0.256.0.0") is None
    assert IP_PATTERN.match("0.255.0.512") is None

    assert IP_LIKE_PATTERN.match("512") is not None
    assert IP_LIKE_PATTERN.match("0.255.0.512") is not None
    assert IP_LIKE_PATTERN.match("0....512") is not None
    assert IP_LIKE_PATTERN.match("1.com") is None

    invalid_domains = [
        "978",  # invalid IP
        "10.10",  # invalid IP
        "10....2",  # invalid IP
        "1.2.3.4.5",  # invalid IP
        "0.256.0.0",  # invalid IP
        "192.168.0.789",  # invalid IP
        "0.0.812.10",  # invalid IP
        "0.0.0.0",  # private IP
        "0.123.0.0",  # private IP
        "0.0.255.0",  # private IP
        "10.0.0.0",  # private IP
        "100.64.0.0",  # private IP
        "100.64.0.255",  # private IP
        "100.99.99.99",  # private IP
        "100.127.255.255",  # private IP
        "192.168.0.10",  # private IP
        "240.0.0.0",  # private IP
        "241.0.127.255",  # private IP
        "255.255.255.255",  # private IP
    ]
    for domain in invalid_domains:
        if not is_invalid_domain(domain):
            fail(f"incorrectly accepted the unexpected domain: '{domain}'")

    regular_domains = [
        "foo.com",
        "0.101.com",
        "100.63.255.0",
        "100.128.0.0",
        "128.0.0.0",
        "169.253.0.0",
        "169.255.0.0",
    ]
    for domain in regular_domains:
        if is_invalid_domain(domain):
            fail(f"incorrectly rejected the regular domain: '{domain}'")


if __name__ == "__main__":
    # test_invalid_domain_patterns()
    generate()
