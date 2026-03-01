package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.Use(func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'self' http://localhost:7766; img-src 'self' data:; style-src 'self';")
		c.Next()
	})

	r.LoadHTMLGlob("/Users/pangaichen/Desktop/shitCode/nests/front/templates/*")
	r.Static("/static", "/Users/pangaichen/Desktop/shitCode/nests/front/static")

	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{})
	})

	r.GET("/checker", func(c *gin.Context) {
		c.HTML(200, "checker.html", gin.H{})
	})

	log.Printf("front listening on :7788")
	if err := r.Run(":7788"); err != nil {
		log.Fatal(err)
	}
}
