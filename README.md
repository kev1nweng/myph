# `myph`

`myph` 是 [`lex`](https://github.com/kev1nweng/lex) 的后端，是 [秘符灵匣 Myphlex](https://github.com/kev1nweng/Myphlex) 的一部分。

## 🚀 部署

1. 克隆该仓库并安装依赖：

```bash
git clone https://github.com/kev1nweng/myph
pip3 install flask flask-cors
```

2. 运行 `myph`：

```bash
python3 myph.py
```

3. 将 `config.example.ini` 重命名为 `config.ini` 并在 `app.py` 中修改端口号使其符合您的需求：

```python
...
if __name__ == "__main__":
    updateOverrides()
    app.run(host=Spec.host, port=your_desired_port_number, debug=Debug.enabled)
```

4.访问您部署的灵匣前端实例，秘符灵匣会自动开始配置向导。
