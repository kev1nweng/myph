import os, struct, hashlib as hl, random, time, sys, argparse


def printa(content):
    print(f"\n{content}", end="")


def printx(content, end=""):
    print(f"\r{content}", end=end)


def getRandomHashSeq():
    hashCollectionLen = 2**15
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


def main(path="./fingerprint"):
    printx("[OK] 正在初始化 (1/4)")
    printa("[..] 生成哈希序列 (2/4)")

    hashSeq = getRandomHashSeq()
    printx("                                    ")
    printx("[OK] 生成哈希序列 (2/4)")

    printa("[..] 构建比特数组 (3/4)")

    hashSeqBytes = bytes.fromhex(hashSeq)
    printx("[OK] 构建比特数组 (3/4)")

    printa(f'[..] 正在写入 "{path}" (4/4)')
    printa(f"\n{hashSeq[:16]}...({len(hashSeq)})")

    if os.path.exists(path):
        print(
            '\n\n警告！指纹文件已经存在。\n对其进行覆写会导致所有与其关联的密码被丢失。\n非常建议在生成一个新指纹之前先备份之前的指纹。\n(输入 "dev" 可以生成一个调试用指纹，但不会覆写指纹文件)'
        )
        print('\n继续覆盖吗？输入 "我知道我在干什么" 来继续。')
        warningQuery = input(">> ")
        if warningQuery != "我知道我在干什么" and warningQuery != ";i":
            if warningQuery == "dev":
                path = path + "-dev"
            else:
                sys.exit(0)
        printa("如果你后悔了现在立刻马上按Ctrl+C！！")
        time.sleep(2)
        printx("                                         ")

    with open(path, "wb") as file:
        file.write(hashSeqBytes)

    printx(f'[OK] 已写入 "{path}" (4/4)')
    printa(f"[OK] 正在退出 ({len(hashSeq) / 2} bytes 已写入)")


# 获取程序运行参数，如果有 --run 则运行 main 函数，否则作为 module
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        main("../fingerprint")
