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
		apiBase := os.Getenv("NESTS_API_BASE")
		if apiBase == "" {
			apiBase = "http://localhost:7766"
		}
		if os.Getenv("NESTS_FORCE_HTTPS") == "1" {
			if c.GetHeader("X-Forwarded-Proto") != "https" && c.Request.TLS == nil {
				url := "https://" + c.Request.Host + c.Request.RequestURI
				c.Redirect(301, url)
				return
			}
		}
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		csp := "default-src 'self'; script-src 'self'; connect-src 'self' " + apiBase + "; img-src 'self' data:; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
		c.Header("Content-Security-Policy", csp)
		c.Next()
	})

	frontDir := os.Getenv("NESTS_FRONT_DIR")
	if frontDir == "" {
		frontDir = "/app/front"
	}
	if _, err := os.Stat(frontDir); err != nil {
		frontDir = "./front"
	}
	r.LoadHTMLGlob(frontDir + "/templates/*")
	r.Static("/static", frontDir+"/static")

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
