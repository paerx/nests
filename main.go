package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"nests/api"
	"nests/bin"
)

func main() {
	port := os.Getenv("NESTS_PORT")
	if port == "" {
		port = "7766"
	}

	dataDir := os.Getenv("NESTS_DATA_DIR")
	if dataDir == "" {
		dataDir = "/Users/pangaichen/Desktop/shitCode/nests/data"
	}

	checkerBase := os.Getenv("NESTS_CHECKER_WEB_BASE")
	if checkerBase == "" {
		checkerBase = "http://localhost:7788" + "/checker"
	}

	store := bin.NewStore(dataDir)
	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	api.RegisterRoutes(r, store, checkerBase)

	log.Printf("nests listening on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}
