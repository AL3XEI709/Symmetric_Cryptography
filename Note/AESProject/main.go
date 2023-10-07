package main 

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "net/http"
    "bytes"
	"fmt"
	"encoding/base64"
    "github.com/gin-gonic/gin"
)


func main() {
	var key []byte
	var iv [] byte 
	sid := getrandbytes(16) 
	key = getrandbytes(16) 
	iv = getrandbytes(16) 

	router := gin.Default() 
	router.LoadHTMLGlob("templates/*") 
	router.StaticFile("/pass.php", "./templates/pass.php") 
	router.StaticFile("/reject.php", "./templates/reject.php") 

	router.GET("/", func(c *gin.Context) {
		token, e := enc(sid, key, iv) 
		check(e) 
		c.SetSameSite(http.SameSiteStrictMode) 
		fmt.Println("sid: "+base64.StdEncoding.EncodeToString(token))
		c.SetCookie("sid", base64.StdEncoding.EncodeToString(token), 0, "/", "", true, true) 
		c.HTML(200, "index.html", nil)
	}) 

	rou

	router.POST("/dec", func(c *gin.Context) {
		ct_ := c.PostForm("ct") 
		ct, e := base64.StdEncoding.DecodeString(ct_) 
		if e != nil {
			c.Redirect(303, "/reject.php") 
			return 
		}
		pt_, e := dec(ct, key, iv) 
		if e != nil || base64.StdEncoding.EncodeToString(pt_) == base64.StdEncoding.EncodeToString(sid){
			c.Redirect(303, "/reject.php") 
			return 
		}
		pt := base64.StdEncoding.EncodeToString(pt_) 
		router.GET("/"+pt, func(c *gin.Context){
			c.HTML(200, "pass.php", nil)
		})

		
	})

	router.Run(":7777")

}

func check(err error) {
    if err != nil {
        panic(err) 
    }
}

func getrandbytes(n int) []byte {
	res := make([]byte, n) 
	_, e := rand.Read(res) 
	check(e) 
	return res 
}

func pad(pt []byte) []byte {
	padlen := aes.BlockSize - (len(pt) % aes.BlockSize) 
	padding := bytes.Repeat([]byte{byte(padlen)}, padlen) 
	return append(pt, padding...) 
}

func unpad(pt []byte) []byte {
	padlen := int(pt[len(pt)-1]) 
	return pt[:len(pt)-padlen] 
}

func enc(pt []byte, key []byte, iv []byte) ([]byte, error) {
	block, e := aes.NewCipher(key) 
	if e != nil {
		return nil, e 
	}
	pt_ := pad(pt) 
	ct := make([]byte, len(pt_)) 
	m := cipher.NewCBCEncrypter(block, iv) 
	m.CryptBlocks(ct, pt_) 
	
	return ct, nil 

}

func dec(ct []byte, key []byte, iv []byte) ([]byte, error) {
	block, e := aes.NewCipher(key) 
	if e != nil {
		return nil, e
	}
	m := cipher.NewCBCDecrypter(block, iv) 
	pt_ := make([]byte, len(ct)) 
	m.CryptBlocks(pt_, ct) 
	
	return unpad(pt_), nil 

}



