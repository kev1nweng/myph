# `myph`

`myph` 是 [`lex`](https://github.com/kev1nweng/lex) 的后端，是 [秘符灵匣 Myphlex](https://github.com/kev1nweng/Myphlex) 的一部分。

## 🚀 部署

1. 克隆该仓库并安装依赖：

```bash
git clone https://github.com/kev1nweng/myph
pip3 install flask flask-cors
```

2. 修改 `config.exmaple.ini` 中的内容并将其重命名为 `config.ini`：

```ini
[pwd]
set = true                  ; 服务器是否正确配置
host = 0.0.0.0              ; Web 服务广播IP
rule = d1-d2-d3-d4          ; 密码规则：yy.mm.dd hh:mm:ss 分别对应 d1d2.d3d4.d5d6 t1t2.t3t4.t5t6
prefix = mL0x               ; 密码前缀
hashlength = 8              ; 密码中间部分长度
seed1segment = 4            ; 密码种子 1 切片长度（用于生成密码中的特殊符号）
seed2segment = 5            ; 密码种子 2 切片长度（用于生成密码中的特殊符号）
suffix = Aa                 ; 密码后缀

```

3. 运行 `myph`：

```bash
python3 myph.py
```
