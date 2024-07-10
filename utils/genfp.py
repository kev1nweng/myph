import os, struct, hashlib as hl, random, time, sys


def printa(content):
    print(f"\n{content}", end="")


def printx(content, end=""):
    print(f"\r{content}", end=end)

def getRandomHashSeq():
    hashCollectionLen = 2 ** 15
    hashSeqCollection = []
    finalHashSeq = ""
    for i in range(hashCollectionLen):
        hashSeqCollection.append(
            hl.sha512(
                str(struct.unpack("Q", os.urandom(8))[0]).encode("utf-8")
            ).hexdigest()
        )
        printx(f"[..] 正在生成哈希序列 ({round(i / hashCollectionLen * 100)}%)")
    for x in range(64):
        random.seed(random.randint(x, i))
        finalHashSeq += random.choice(hashSeqCollection)
    return finalHashSeq

def main():
    printx("[OK] Initializing (1/4)")


    printa("[..] Generating hash sequence (2/4)")

    hashSeq = getRandomHashSeq()
    printx("                                    ")
    printx("[OK] Generating hash sequence (2/4)")

    printa("[..] Building byte array (3/4)")

    hashSeqBytes = bytes.fromhex(hashSeq)
    printx("[OK] Building byte array (3/4)")

    printa('[..] Writing data to "./fingerprint" (4/4)')

    printa(f"\n{hashSeq[:16]}...({len(hashSeq)})")

    fingerprintFileName = "fingerprint"
    if os.path.exists("fingerprint"):
        print(
            '\n\nWARNING!! FILE "fingerprint" ALREADY EXISTS. \nOVERWRITING COULD LEAD TO A COMPLETE LOSS OF ALL PASSWORDS LINKED TO THE FINGERPRINT. \nIT IS STRONGLY RECOMMENDED TO BACKUP THE FINGERPRINT FILE BEFORE GENERATING A NEW ONE. \n(Insert "dev" to generate a dev sample)'
        )
        print('\nOverwrite anyway? Type "I know what I am doing" to proceed.')
        warningQuery = input(">> ")
        if warningQuery != "I know what I am doing" and warningQuery != ";i":
            if warningQuery == "dev":
                fingerprintFileName = "fingerprint_dev"
            else:
                sys.exit(0)
        printa("PRESS CTRL+C RIGHT NOW IF YOU REGRET IT!!")
        time.sleep(2)
        printx("                                         ")

    with open(fingerprintFileName, "wb") as file:
        file.write(hashSeqBytes)
    printx('[OK] Writing data to "./fingerprint" (4/4)')

    printa(f"[OK] Qutting ({len(hashSeq) / 2} bytes written)")
