package main

import (
	"log"
	"os"

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
		apiBase := os.Getenv("NESTS_API_BASE")
		if apiBase == "" {
			apiBase = "http://localhost:7766"
		}
		c.HTML(200, "index.html", gin.H{
			"apiBase": apiBase,
		})
	})

	r.GET("/checker", func(c *gin.Context) {
		apiBase := os.Getenv("NESTS_API_BASE")
		if apiBase == "" {
			apiBase = "http://localhost:7766"
		}
		c.HTML(200, "checker.html", gin.H{
			"apiBase": apiBase,
		})
	})

	log.Printf("front listening on :7788")
	if err := r.Run(":7788"); err != nil {
		log.Fatal(err)
	}
}
