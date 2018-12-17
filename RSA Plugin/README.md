# RSA Plugin

用于快速替换 RSA 加解密结果

## 安装

1. 首先安装 jython
```bash
brew install jython
```

2. 使用 jython 下的 pip 安装 rsa 库
```bash
cd $(brew --cellar)/jython/2.7.1/libexec/bin && ./pip install rsa
```

3. Burp 中配置 jython 环境并加载 RSAPlugin.py

## 可选项

1. `auto-replace`：每当加解密结束后，勾选这项会将选择的被加解密文本替换为结果
2. `urlcode Enable`：如果在执行解密前、加密后需要对选择的文本进行url编码，勾选此项

## 注意

1. 由于 rsa 包对私钥只支持 PKCS#1 格式进行加解密，如果是 PKCS#8 需要手动转换 

## Q&A

1. 为什么不兼容更多的格式，因为支持库在jython中不好加载(M2Crypto, pycrypto我尝试都不行，如果有成功的请指导我一下Orz)
2. 为什么菜单要分request/response，因为 Burp 还未开放直接替换文本的 API，导致必须通过覆盖全部文本来替换

## 效果

![image](https://github.com/sari3l/Burp-Extensions/blob/master/RSA%20Plugin/images/Demonstration.gif)