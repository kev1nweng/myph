import flask as fl
from threading import Thread
import time, datetime, random, hashlib, sys, configparser, signal
from utils import genfp
from flask_cors import CORS

# 配置读取
config = configparser.ConfigParser()
try:
    config.read("config.ini")
except Exception as e:
    print("\n[-] 未找到配置。程序正在退出...\n")
    sys.exit(0)


app = fl.Flask(__name__)
CORS(app)


class Debug:
    enabled = False
    simulatedDelay = 2

    def sleep():
        time.sleep(Debug.simulatedDelay if Debug.enabled else 0)


class Runtime:
    class token:
        value = None
        updateTime = None
        accessBuffer = 0

    class fingerprint:
        md5 = None

    def antiBruteforce():
        if Runtime.token.accessBuffer > 5:
            print("\n[!] **疑似攻击** 已阻塞过于频繁的请求。\n")
            fl.abort(418)


# 读取用户指纹，若没有指纹则进行生成
while True:
    try:
        with open("./fingerprint", "rb") as file:
            fingerprint = file.read(4096).hex()
            Runtime.fingerprint.md5 = hashlib.md5(
                fingerprint.encode("utf-8")
            ).hexdigest()
            print(f"\n[+] 已找到指纹。 文件的 md5 是 {Runtime.fingerprint.md5}\n")
        break
    except Exception as e:
        print(f"\n[-] 未找到指纹。正在生成...\n")
        genfp.main()
        continue


# 存储密码特征信息
class Spec:
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


def updateConfig():
    global Spec
    config.read("config.ini")
    try:
        Spec.set = str(config.get("pwd", "set"))
        Spec.rule = str(config.get("pwd", "rule"))
        Spec.host = str(config.get("pwd", "host"))
        Spec.prefix = str(config.get("pwd", "prefix"))
        Spec.hashlength = int(config.get("pwd", "hashlength"))
        Spec.sg1 = int(config.get("pwd", "seed1segment"))
        Spec.sg2 = int(config.get("pwd", "seed2segment"))
        Spec.suffix = str(config.get("pwd", "suffix"))
    except BaseException:
        print("\n[-] 配置已损坏。程序正在退出...\n")
        sys.exit(0)


if Spec.set == "false":
    print("[!] 服务器未正确配置。\n")


# 生成10分钟有效期的会话令牌
def generateToken():
    global Runtime, Runtime
    sKey = hashlib.md5(str(random.random()).encode()).hexdigest()
    Runtime.token.value = sKey
    Runtime.token.updateTime = datetime.datetime.now()
    return sKey


# 获取服务器状态的接口
@app.route("/ping")
def index():
    global Runtime
    Debug.sleep()
    return fl.jsonify({"fingerprint": Runtime.fingerprint.md5, "setup": Spec.set})


@app.route("/submitConfig")
def submitConfig():
    global config, updateConfig, Runtime

    if (fl.request.args.get("token") != Runtime.token.value) and Spec.set == True:
        fl.abort(403)

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
    print("\n[!] 配置文件已更改。\n")
    updateConfig()
    print("[i] 配置热重载完成。\n")
    Debug.sleep()
    return fl.jsonify({"status": "success"})


# 秘符验证接口（基于当前时间的动态密码）
@app.route("/auth/<string:key>")
def auth(key):
    global Runtime
    Runtime.token.accessBuffer += 1
    Runtime.antiBruteforce()

    now = datetime.datetime.now()
    year = str(now.year % 100)
    year = str(now.year % 100)
    month = str(now.month).zfill(2)
    day = str(now.day).zfill(2)
    hour = str(now.hour).zfill(2)
    minute = str(now.minute).zfill(2)
    second = str(now.second).zfill(2)

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
        for i in Spec.rule.split("-"):
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
    Debug.sleep()

    if key == dynamicComputedSequence:
        ntk = generateToken()
        print(f"\n[+] Access granted for {Runtime.token.value}.\n")
        return {"access": True, "token": ntk}
    else:
        print(
            f"\n[-] 已拒绝访问，因为提供的秘符 {key} 与预期序列 {dynamicComputedSequence} 不匹配。\n"
        )
        if Runtime.token.value is not None:
            if key != "-logout-":
                print(
                    f"[!] 由于出现验证故障，正在使密钥 {Runtime.token.value} 失效。 \n"
                    # 安全措施，若另一个用户在别处输入了错误的密码则一刀切使所有会话失效，有待商榷？
                )
            else:
                print("[!] 收到注销会话请求，正在使会话密钥失效 \n")
            Runtime.token.value = None
        return {"access": False, "token": None}


# 获取密码的接口
@app.route("/fetchKey")
def api():
    global Runtime
    Runtime.token.accessBuffer += 1
    Runtime.antiBruteforce()

    # activeSessionToken 为实现会话有效期使用的动态 token
    # pwdSpec 为包含了用户自定义密码规则的 class
    token = fl.request.args.get("token")
    if token != Runtime.token.value:
        fl.abort(401)
    inputStr = fl.request.args.get(
        "id"
    ).upper()  # 该变量为用户提供的平台名称的 SHA1 不可逆加密结果
    calcid = f"{inputStr}-{fingerprint}"
    symbols = ["!", "@", "#", "$", "&", "%", "/"]  # 使用符号增加密码复杂度
    hashPart = hashlib.sha256(calcid.encode(encoding="utf-8")).hexdigest()[
        : Spec.hashlength
    ]
    # 使用哈希序列的切片作为随机种子
    seeds = [hashPart[: Spec.sg1], hashPart[: Spec.sg2]]
    symbolPart = ""
    for seed in seeds:
        random.seed(seed)
        symbolPart += random.choice(symbols)
    # 凭借不同部分组成密码并返回
    pwd = Spec.prefix + hashPart + symbolPart + Spec.suffix

    Debug.sleep()
    return {"id": inputStr, "pwd": pwd}


# 获取服务器配置状态的接口
@app.route("/cfgStatus")
def getIsConfigured():
    global Spec
    if Spec.set == "true":
        return fl.jsonify({"configured": True})
    else:
        return fl.jsonify({"configured": False})


# 重置会话令牌的函数
def tokenDaemonPayload():
    global Runtime
    now = datetime.datetime.now()
    expiry = datetime.timedelta(minutes=10)
    if Runtime.token.value is None:
        return
    if Runtime.token.value is not None and now > Runtime.token.updateTime + expiry:
        print(f"\n[!] 活动的会话令牌 {Runtime.token.value} 已过期。 \n")
        Runtime.token.value = None
        Runtime.token.updateTime = None


# 定期expire会话令牌的线程
def activeSessionTokenMonitor():
    global Runtime
    while True:
        tokenDaemonPayload()
        Runtime.token.accessBuffer = (
            Runtime.token.accessBuffer - 1 if Runtime.token.accessBuffer > 0 else 0
        )
        time.sleep(1)


sessionTokenMonitor = Thread(target=activeSessionTokenMonitor, daemon=True)
sessionTokenMonitor.start()


# ^C处理函数
def signalHandler(signal, frame):
    signal, frame  # 防止提示变量未使用
    print("\n[!] 正在退出")
    sys.exit(0)


signal.signal(signal.SIGINT, signalHandler)

if __name__ == "__main__":
    app.run(host=Spec.host, port=4518, debug=Debug.enabled)
