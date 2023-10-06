---
title: My_Error_Genie
date: 2023-03-22 18:43:59
tags:
---

burpsuite抓到的包的各个部分是什么

```
Burp Suite是一款用于Web应用程序安全测试的工具，它可以拦截并分析HTTP请求和响应。Burp Suite抓到的包主要由以下几个部分组成：

请求行：包含请求方法（GET、POST等）、请求URI和HTTP协议版本。
请求头：包含请求相关的各种元数据，例如User-Agent、Referer、Cookie等。
请求正文：POST请求中包含的参数和数据，以及文件上传时包含的文件数据。
响应行：包含HTTP协议版本、状态码和状态描述。
响应头：包含响应相关的各种元数据，例如Content-Type、Content-Length、Set-Cookie等。
响应正文：响应的主体内容，通常是HTML、JSON、XML或其他格式的数据。
Burp Suite还提供了各种工具和插件，可以帮助安全测试人员进行漏洞扫描、渗透测试和漏洞利用等操作。
```



### 0x1 session & cookie

Session：在计算机中，尤其是在网络应用中，称为“会话控制”。Session对象存储特定用户会话所需的属性及配置信息。这样，当用户在应用程序的Web页之间跳转时，存储在Session对象中的变量将不会丢失，而是在整个用户会话中一直存在下去。当用户请求来自应用程序的 Web页时，如果该用户还没有会话，则Web服务器将自动创建一个 Session对象。当会话过期或被放弃后，服务器将终止该会话。

<img src="https://img-blog.csdnimg.cn/20200810201646714.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3hkazIxNjY=,size_16,color_FFFFFF,t_70" style="zoom:50%;" />

- session是服务端存储的一个对象，主要用来存储所有访问过该服务端的客户端的用户信息（也可以存储其他信息），从而实现保持用户会话状态。但是服务器重启时，内存会被销毁，存储的用户信息也就消失了。
- 不同的用户访问服务端的时候会在session对象中存储键值对，“键”用来存储开启这个用户信息的“钥匙”，在登录成功后，“钥匙”通过cookie返回给客户端，客户端存储为sessionId记录在cookie中。当客户端再次访问时，会默认携带cookie中的sessionId来实现会话机制。
- session是基于cookie的。



基于攻防世界的cookie题目学习一下它的传输形式

bp抓包，在Request Cookies发现这个键值对：

```
name           value 
look-here      cookie.php
```

> cookie信息位于headers的set-cookie字段。有多少个cookie信息加入就有多少个set-cookie字段。

> go 官方档案有毒，`setcookie`的url参数应该是http://localhost，它写一个localhost谁知道啊……

构造产生随机64bytes的cookie:

```go
func main() {

	router := gin.Default()

	router.GET("/upload", func(c *gin.Context) {

		cookie, err := c.Cookie("__geniesid")

		if err != nil {
			cookie = "NotSet"
			//testid := "114"
			geniesid := make([]byte, 64)
			_, rerr := rand.Read(geniesid)
			if rerr != nil {
				fmt.Println("error:", rerr)
				return
			}
			hgeniesid := hex.EncodeToString(geniesid)
			c.SetCookie("__geniesid", hgeniesid, 30, "/", "http://localhost", false, true)
		}

		fmt.Printf("Cookie value: %s \n", cookie)
	})

	router.Run(":8082")
}
```



### 文件上传

`curl -X POST http://127.0.0.1:8082/upload -F "upload=@C:/Users/Admin/a.txt" -H "Content-Type: multipart/form-data"`

```go
	g.POST("/upload", func(c *gin.Context) {
		file, header, err := c.Request.FormFile("upload")
		if err != nil {
			c.String(200, "Bad Request.\n")
			log.Fatal(err)
			return
		}
		filename := header.Filename
		out, err := os.Create(".\\upload\\" + filename)
		if err != nil {
			log.Fatal(err)
		}
		defer out.Close()
		_, err = io.Copy(out, file)
		if err != nil {
			log.Fatal(err)
		}
		c.String(200, "upload OK.\n")
	})
```

### 序列化 & 反序列化

```go
type Body struct {
	Name string `json:"name"`
}
g.POST("serialize", func(c *gin.Context) {
		body := Body{}
		if err := c.BindJSON(&body); err != nil {
			log.Fatal(err)
			return
		}
		fmt.Println(body)
		c.JSON(200, &body)
	})

```

`cursor`编程



### AES implement

copied from Ljahum 🍔

```go 
import (
	"fmt"
	"myaes"
)

func main() {

	output := myaes.EncryptCbcMode([]byte{'t', 'e', 's', 't'}, []byte{'t'})
	output1 := fmt.Sprintf("%x", string(output[:16]))
	fmt.Println("\n密文", output1)
}
```



```go
package main

import (
	//"fmt"
	"io"
	"net/http"
	"os"

	//"path/filepath"
	//"strconv"

	"github.com/gin-gonic/gin"
)

// 用于存储用户信息的结构体
type User struct {
	Username string
	Password string
}

// 用于存储上传文件信息的结构体
type File struct {
	Username string
	Filename string
	Filepath string
}

// 用于存储用户信息的map，key为用户名，value为User结构体
var users = make(map[string]User)

// 用于存储上传文件信息的slice，每个元素为File结构体
var files []File

func main() {
	router := gin.Default()

	// 注册页面
	router.GET("/register", func(c *gin.Context) {
		c.String(http.StatusOK, "register.html", nil)
	})

	// 处理注册请求
	router.POST("/register", func(c *gin.Context) {
		// 从POST请求中获取用户名和密码
		username := c.PostForm("username")
		password := c.PostForm("password")

		// 检查用户名是否已被注册
		if _, ok := users[username]; ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
			return
		}

		// 将用户信息存储到users map中
		users[username] = User{Username: username, Password: password}

		// 跳转到登录页面
		c.Redirect(http.StatusFound, "/login")
	})

	// 登录页面
	router.GET("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "login.html", nil)
	})

	// 处理登录请求
	router.POST("/login", func(c *gin.Context) {
		// 从POST请求中获取用户名和密码
		username := c.PostForm("username")
		password := c.PostForm("password")

		// 检查用户名和密码是否正确
		if user, ok := users[username]; ok && user.Password == password {
			// 登录成功，设置cookie
			c.SetCookie("username", username, 300, "/", "", false, true)
			c.Redirect(http.StatusFound, "/")
		} else {
			// 登录失败，返回错误信息
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid username or password"})
		}
	})

	// 上传文件页面
	router.GET("/upload", func(c *gin.Context) {
		c.String(http.StatusOK, "upload.html", nil)
	})

	// 处理上传文件请求
	router.POST("/upload", func(c *gin.Context) {
		// 从cookie中获取用户名
		username, err := c.Cookie("username")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please login first"})
			return
		}

		// 获取上传的
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get file"})
			return
		}
		defer file.Close()

		// 创建用户文件夹（如果不存在）
		userFolder := "./" + username
		if _, err := os.Stat(userFolder); os.IsNotExist(err) {
			os.Mkdir(userFolder, os.ModePerm)
		}

		// 创建上传文件的文件路径
		filename := header.Filename
		filepath := userFolder + "/" + filename

		// 创建新的File结构体，并将其添加到files slice中
		newFile := File{Username: username, Filename: filename, Filepath: filepath}
		files = append(files, newFile)

		// 创建文件并保存文件内容
		out, err := os.Create(filepath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create file"})
			return
		}
		defer out.Close()
		_, err = io.Copy(out, file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
			return
		}

		// 上传成功，返回成功信息
		c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully"})
	})

	// 查看所有文件页面
	router.GET("/", func(c *gin.Context) {
		// 从cookie中获取用户名
		username, err := c.Cookie("username")
		if err != nil {
			username = ""
		}

		// 构造包含所有文件信息的slice
		allFiles := make([]File, len(files))
		copy(allFiles, files)

		// 根据用户名过滤文件信息
		if username != "" {
			filteredFiles := []File{}
			for _, file := range allFiles {
				if file.Username == username {
					filteredFiles = append(filteredFiles, file)
				}
			}
			allFiles = filteredFiles
		}

		// 将文件信息传递给HTML模板进行渲染
		c.JSON(http.StatusOK, gin.H{"username": username, "files": allFiles})
	})

	// 静态文件服务
	//router.Static("/static", "./static")

	// 加载HTML模板
	//router.LoadHTMLGlob("templates/*")

	// 启动服务器
	router.Run(":8082")
}

```

