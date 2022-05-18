
from consts import TOP_ALEXA_URLS, KEYBOARD_ADJACENT_CHARS_MAPPING


def get_url_host_name(raw_url: str):
    final_url = raw_url.split(',')[1].strip()
    if final_url[:3] != 'www':
        final_url = f"www.{final_url}"

    return final_url


suspicious_sites = set()
for url in TOP_ALEXA_URLS:
    host_name = get_url_host_name(url)

    site_prefix = host_name.split('.')[0]  # www
    site_name = host_name.split('.')[1]  # google
    tld = host_name.split('.', 2)[2]  # com

    # missing-dot typos:
    url_as_list = host_name.split('.', 1)
    suspicious_url = ''.join(url_as_list)
    suspicious_sites.add(suspicious_url)

    # Character-omission typos:
    for i in range(len(site_name)):
        suspicious_site_name = site_name[0: i] + site_name[i+1: len(site_name)]
        suspicious_site_domain = f"{site_prefix}.{suspicious_site_name}.{tld}"
        suspicious_sites.add(suspicious_site_domain)

    # Character-permutation typos:
    for i in range(len(site_name) - 1):
        if site_name[i] != site_name[i + 1]:
            suspicious_site_name = site_name[:i] + site_name[i + 1] + site_name[i] + site_name[i + 2:]
            suspicious_site_domain = f"{site_prefix}.{suspicious_site_name}.{tld}"
            suspicious_sites.add(suspicious_site_domain)

    # Character-replacement typos and Character-insertion typos:
    for i in range(len(site_name)):
        char = site_name.lower()[i]
        if char.isalpha():
            for adjacent_char in KEYBOARD_ADJACENT_CHARS_MAPPING[char]:
                if char == adjacent_char:
                    suspicious_site_name = site_name[:i + 1] + site_name[i:]
                else:
                    suspicious_site_name = site_name[:i] + adjacent_char + site_name[i + 1:]

                suspicious_site_domain = f"{site_prefix}.{suspicious_site_name}.{tld}"
                suspicious_sites.add(suspicious_site_domain)