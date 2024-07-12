import flask as fl
from threading import Thread
import time, datetime, random, hashlib, sys, configparser, signal
from utils import genfp
from flask_cors import CORS

config = configparser.ConfigParser()
try:
    config.read("config.ini")
except Exception as e:
    print("\n[-] 未找到配置。程序正在退出...\n")
    sys.exit(0)


app = fl.Flask(__name__)
CORS(app)

globalDelay = 0
debugMode = False

if debugMode:
    globalDelay = 2
else:
    globalDelay = 0

activeSessionToken = None
tokenUpdateTime = None

while True:
    try:
        with open("./fingerprint", "rb") as file:
            fingerprint = file.read(4096).hex()
            print(
                f"\n[+] 已找到指纹。 文件的 md5 是 {hashlib.md5(fingerprint.encode('utf-8')).hexdigest()}\n"
            )
        break
    except Exception as e:
        print(f"\n[-] 未找到指纹。正在生成...\n")
        genfp.main()
        continue


class pwdSpec:

    try:
        set = str(config.get("pwd", "set"))
        rule = str(config.get("pwd", "rule"))
        host = str(config.get("pwd", "host"))
        prefix = str(config.get("pwd", "prefix"))
        hashlength = int(config.get("pwd", "hashlength"))
        sg1 = int(config.get("pwd", "seed1segment"))
        sg2 = int(config.get("pwd", "seed2segment"))
        suffix = str(config.get("pwd", "suffix"))
    except BaseException:
        print("\n[-] 配置已损坏。程序正在退出...\n")
        sys.exit(0)


if pwdSpec.set == "false":
    print("[!] 服务器未正确配置。\n")


def generateToken():
    global activeSessionToken, tokenUpdateTime
    sKey = hashlib.md5(str(random.random()).encode()).hexdigest()
    activeSessionToken = sKey
    tokenUpdateTime = datetime.datetime.now()
    return sKey


def debugSleep():
    time.sleep(globalDelay)


@app.route("/ping")
def index():
    debugSleep()
    return "Hello World"


@app.route("/submitConfig")
def submitConfig():
    global config

    class pwdConfigParams:
        dateTimeRule = str(fl.request.args.get("rule"))
        prefix = str(fl.request.args.get("prefix"))
        hashLength = str(fl.request.args.get("hashlength"))
        seed1Segment = str(fl.request.args.get("s1s"))
        seed2Segment = str(fl.request.args.get("s2s"))
        suffix = str(fl.request.args.get("suffix"))

    config.set("pwd", "set", "true")
    config.set("pwd", "rule", pwdConfigParams.dateTimeRule)
    config.set("pwd", "prefix", pwdConfigParams.prefix)
    config.set("pwd", "hashlength", pwdConfigParams.hashLength)
    config.set("pwd", "seed1segment", pwdConfigParams.seed1Segment)
    config.set("pwd", "seed2segment", pwdConfigParams.seed2Segment)
    config.set("pwd", "suffix", pwdConfigParams.suffix)
    with open("config.ini", "w") as configfile:
        config.write(configfile)
    print("\n[!] 配置文件已更改。请重启服务端来应用这些变化。\n")
    debugSleep()
    return fl.jsonify({"status": "success"})


@app.route("/auth/<string:key>")
def auth(key):
    global activeSessionToken, pwdSpec
    now = datetime.datetime.now()
    year = str(now.year % 100)
    month = now.month
    if month < 10:
        month = "0" + str(month)
    else:
        month = str(month)
    day = now.day
    if day < 10:
        day = "0" + str(day)
    else:
        day = str(day)
    hour = now.hour
    if hour < 10:
        hour = "0" + str(hour)
    else:
        hour = str(hour)
    minute = now.minute
    if minute < 10:
        minute = "0" + str(minute)
    else:
        minute = str(minute)
    second = now.second
    if second < 10:
        second = "0" + str(second)
    else:
        second = str(second)

    class snippets:
        [d1, d2, d3, d4, d5, d6, t1, t2, t3, t4, t5, t6] = [
            year[:1],
            year[:2][-1],
            month[:1],
            month[:2][-1],
            day[:1],
            day[:2][-1],
            hour[:1],
            hour[:2][-1],
            minute[:1],
            minute[:2][-1],
            second[:1],
            second[:2][-1],
        ]

    def getDnComSeq():
        seq = ""
        for i in pwdSpec.rule.split("-"):
            match i:
                case "d1":
                    seq += snippets.d1
                case "d2":
                    seq += snippets.d2
                case "d3":
                    seq += snippets.d3
                case "d4":
                    seq += snippets.d4
                case "d5":
                    seq += snippets.d5
                case "d6":
                    seq += snippets.d6
                case "t1":
                    seq += snippets.t1
                case "t2":
                    seq += snippets.t2
                case "t3":
                    seq += snippets.t3
                case "t4":
                    seq += snippets.t4
                case "t5":
                    seq += snippets.t5
                case "t6":
                    seq += snippets.t6
        return seq

    dynamicComputedSequence = getDnComSeq()
    debugSleep()

    if key == dynamicComputedSequence:
        ntk = generateToken()
        print(f"\n[+] Access granted for {activeSessionToken}.\n")
        return {"access": True, "token": ntk}
    else:
        print(
            f"\n[-] 已拒绝访问，因为提供的秘符 {key} 与预期序列 {dynamicComputedSequence} 不匹配。\n"
        )
        if activeSessionToken is not None:
            if key != "-logout-":
                print(
                    f"[!] 由于出现验证故障，正在使密钥 {activeSessionToken} 失效。 \n"
                )
            else:
                print("[!] 收到注销会话请求，正在使会话密钥失效 \n")
            activeSessionToken = None
        return {"access": False, "token": None}


@app.route("/fetchKey")
def api():
    # activeSessionToken 为实现会话有效期使用的动态 token
    # pwdSpec 为包含了用户自定义密码规则的 class
    global activeSessionToken, pwdSpec
    token = fl.request.args.get("token")
    if token != activeSessionToken:
        fl.abort(403)
    inputStr = fl.request.args.get("id").upper()  # 该 id 参数为用户提供的平台名称
    calcid = f"{inputStr}-{fingerprint}"
    symbols = ["!", "@", "#", "$", "&", "%", "/"]  # 使用符号增加密码复杂度
    hashPart = hashlib.sha256(calcid.encode(encoding="utf-8")).hexdigest()[
        : pwdSpec.hashlength
    ]
    # 使用哈希序列的切片作为随机种子
    seeds = [hashPart[: pwdSpec.sg1], hashPart[: pwdSpec.sg2]]
    symbolPart = ""
    for seed in seeds:
        random.seed(seed)
        symbolPart += random.choice(symbols)
    # 凭借不同部分组成密码并返回
    pwd = pwdSpec.prefix + hashPart + symbolPart + pwdSpec.suffix

    debugSleep()
    return {"id": hashlib.md5(inputStr.encode("utf-8")).hexdigest(), "pwd": pwd}


@app.route("/cfgStatus")
def getIsConfigured():
    global pwdSpec
    if pwdSpec.set == "true":
        return fl.jsonify({"configured": True})
    else:
        return fl.jsonify({"configured": False})


def resetActiveSessionToken():
    global activeSessionToken, tokenUpdateTime
    now = datetime.datetime.now()
    expiry = datetime.timedelta(minutes=10)
    if activeSessionToken is None:
        return
    if activeSessionToken is not None and now > tokenUpdateTime + expiry:
        print(f"\n[!] Active session token {activeSessionToken} expired. \n")
        activeSessionToken = None
        tokenUpdateTime = None


def activeSessionTokenMonitor():
    while True:
        resetActiveSessionToken()
        time.sleep(1)


sessionTokenMonitor = Thread(target=activeSessionTokenMonitor, daemon=True)
sessionTokenMonitor.start()


def signalHandler(signal, frame):
    print("\n[!] Quitting (triggered by Ctrl + C)")
    sys.exit(0)


signal.signal(signal.SIGINT, signalHandler)

if __name__ == "__main__":
    app.run(host=pwdSpec.host, port=4518, debug=debugMode)
