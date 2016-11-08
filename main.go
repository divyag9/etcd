package main

import (
	"fmt"

	"github.com/divyag9/etcd/packages/client"
)

func main() {
	err := client.NewClient("etcd", "tcp", "sgtec.io", "C:/Safeguard/AppCerts/Default/default.cer", "C:/Safeguard/AppCerts/Default/default.key")
	if err != nil {
		fmt.Println("Error: ", err)
	}
}
