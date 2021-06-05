from sys import argv
import re

spaces = " "*4
count = 0

if len(argv) != 2:
    exit("usage: "+argv[0]+" <ip list>")

print("{\n"+spaces+"(addrlist_entry_t[]) {")
with open(argv[1]) as fp:
    for line in fp:
        line = line.strip()
        if re.fullmatch(r"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}", line) is not None:
            if count:
                print(",")
            print((spaces*2)+f"/* {line} */ "+r"{{(uint8_t[]){"+line.replace(".", ",")+"}, IPV4},32}", end="")
            count += 1
        if re.fullmatch(r"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]+", line) is not None:
            if count:
                print(",")
            print((spaces*2)+f"/* {line} */ "+r"{{(uint8_t[]){"+line.split("/")[0].replace(".", ",")+"}, IPV4},"+line.split("/")[1]+"}", end="")
            count += 1
print(",\n"+spaces+"},\n"+spaces+str(count)+"\n}")