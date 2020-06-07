import os

domains = {}


with open("hosts_whitelist", "r") as file:
    hosts_whitelist = set(line.strip() for line in file.readlines()
                          if not line.startswith("#") and line.strip() != "")
# print("- hosts_whitelist:", hosts_whitelist)

host_files = [
    *(f"to_block/{name}" for name in sorted(os.listdir("to_block"))),
    *(f"to_block_dl/{name}" for name in sorted(os.listdir("to_block_dl"))),
]
# print("- host_files:", host_files)

last_ok_domain = "--"

for path in host_files:
    if path == ".DS_Store":
        continue
    print(f"\n# reading '{path}'")
    with open(path, "rt") as file:
        newCnt = 0
        dupCnt = 0
        dups = []
        try:
            for line in file:
                last_ok_domain = line
                # print(f"  + {line}")
                if line.startswith("#"): continue
                if line.find("#") > -1:
                    line = line.split("#")[0]
                    if line.find("#") > -1:
                        print("- contains #: {}".format(line.split("#")))
                line = line.strip()
                if len(line) == 0:
                    continue
                for domain in line.split():
                    domain = domain.strip()
                    # if domain == "127.0.0.1": continue

                    # check if this domain needs to be ignored:
                    if domain in hosts_whitelist:
                        # print(" - ignore: ", domain)
                        continue

                    # check if this domain is already added:
                    if domain in domains:
                        # print(" - found duplicate '" + domain + "'")
                        dupCnt += 1
                        dups.append(domain)
                    else:
                        domains[domain] = True
                        newCnt += 1

            print(f" - added {newCnt} domains")
            if dupCnt > 0:
                print(f" - found {dupCnt} duplicates")
                # for domain in dups:
                #     print("   - ", domain)y
        except UnicodeDecodeError as err:
            print(err)
            print(f"last OK domain: {last_ok_domain}")

print(f"\n# total domain: {len(domains)}")

with open("hosts_result", "wt") as outf:
    with open("hosts_base", "rt") as inf:
        outf.write(inf.read())
    domains = sorted(domains.keys())
    # print(f"- domains: {domains}")
    for domain in domains:
        outf.write("\n127.0.0.1 " + domain)
