# CTF MCP Server

CTF MCP Server 是一个专为CTF（Capture The Flag）比赛设计的多功能密码学工具服务器。它提供了多种密码学相关的功能，帮助参赛者快速解决密码学挑战。

## 功能列表

- **aes_decrypt**: 支持解密各种模式下的AES加密数据
- **base64**: 用于编码或解码base64字符串
- **caesar**: 对输入执行凯撒密码移位
- **calculate**: 执行基本数学运算
- **frequency_analysis**: 对文本进行频率分析
- **rsa_factor_n**: 尝试分解一个大数
- **vigenere_decrypt**: 解密Vigenère密码
- **xor_cipher**: 执行XOR加密/解密

## 配置方式

```json
{
  "ctf_mcp_server": {
    "command": "D:/MCPServer/ctf_mcp_server.exe",
    "args": [],
    "env": {}
  }
}