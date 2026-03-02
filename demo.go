package main

import (
	"example.com/mod/sdk"
	"fmt"
	"log"
	"os"
)

func main() {
	baseURL := "http://localhost:7766"
	name := "test"
	if len(os.Args) >= 2 {
		name = os.Args[1]
	}
	if len(os.Args) >= 3 {
		baseURL = os.Args[2]
	}

	client := sdk.Init(baseURL)
	var values map[string]string
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		values, err = client.GetConfig(name)
		if err != nil {
			log.Fatal(err)
		}
		if client.Recheck(values) {
			break
		}
		fmt.Println("detected garbled output, retrying...")
	}
	if !client.Recheck(values) {
		log.Fatal("garbled output after retries")
	}
	fmt.Printf("env: %s\n", name)
	for k, v := range values {
		fmt.Printf("%s = %s\n", k, v)
	}
}
