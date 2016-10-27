package main

import "github.com/divyag9/etcd/packages/client"

func main() {
	client.NewClient("etcd", "tcp", "sgtec.io", "C:/Safeguard/AppCerts/Default/default.cer", "C:/Safeguard/AppCerts/Default/default.key")
}
