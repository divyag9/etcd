package client

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/etcd/client"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/net/context"
)

// Client has all the information required to connect to etcd and retrieve the key value store
type Client struct {
	endpoints     []string
	httpTransport *http.Transport
	entity        *openpgp.Entity
}

//GetEndpoints returns list of end points retrieved from srv record
func (c *Client) GetEndpoints(service, proto, domain string) (err error) {
	_, addrs, err := net.LookupSRV(service, proto, domain)
	var urls []*url.URL
	for _, srv := range addrs {
		urls = append(urls, &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(srv.Target, fmt.Sprintf("%d", srv.Port)),
		})
	}
	c.endpoints = make([]string, len(urls))
	for i := range urls {
		c.endpoints[i] = urls[i].String()
		//strings.TrimSuffix(".", urls[i].String())
	}
	//c.endpoints = []string{"https://etcd00.dev02.local:2379/v2/keys/"}
	fmt.Println(c.endpoints)

	return
}

//GetHTTPTransport http transport for the cert and key
func (c *Client) GetHTTPTransport(cert, key string) (err error) {
	if cert == "" || key == "" {
		return errors.New("Require both cert and key path")
	}
	fmt.Println("publicKeyTest start")
	tlsCert, err := tls.LoadX509KeyPair(cert, key)
	certx509, _ := ioutil.ReadFile(cert)

	block, _ := pem.Decode([]byte(certx509))
	certTest, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}

	privateKeyTest := tlsCert.PrivateKey

	config := &packet.Config{}
	config.DefaultCompressionAlgo = 1
	config.DefaultCipher = 9
	config.DefaultHash = 3
	c.entity, _ = openpgp.NewEntity("", "", "", config)
	c.entity.PrimaryKey.PubKeyAlgo = 1
	c.entity.PrimaryKey.PublicKey = (certTest.PublicKey).(*rsa.PublicKey)
	c.entity.PrivateKey.PrivateKey = privateKeyTest.(*rsa.PrivateKey)
	c.entity.PrivateKey.PublicKey.PubKeyAlgo = 1
	c.entity.PrivateKey.PublicKey.PublicKey = (certTest.PublicKey).(*rsa.PublicKey)

	//fmt.Println("privateKeyTest: ", privateKeyTest)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
	}
	c.httpTransport = &http.Transport{
		TLSClientConfig: tlsConfig,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
	}

	return
}

// NewClient does...
func NewClient(service, proto, domain, cert, key string) {
	c := &Client{}
	c.GetEndpoints(service, proto, domain)
	c.GetHTTPTransport(cert, key)
	cfg := client.Config{
		Endpoints: c.endpoints,
		Transport: c.httpTransport,
		// set timeout per request to fail fast when the target endpoint is unavailable
		HeaderTimeoutPerRequest: time.Second,
	}
	cli, err := client.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	kapi := client.NewKeysAPI(cli)

	resp, err := kapi.Get(context.Background(), "/TestEtcd/461046A0297D5848D5510BE07A37D03F6180BF17/Foo", nil)
	if err != nil {
		log.Fatal(err)
	} else {
		// print common key info
		fmt.Printf("Get is done. Metadata is %q\n", resp)
		//fmt.Println("pgp value: ", resp.Node.Value)
		// print value
		fmt.Printf("%q key has %q value\n", resp.Node.Key, DecryptValue(resp.Node.Value, key, c.entity))
	}
}

// DecryptValue does...
func DecryptValue(encryptedMessage string, privateKey string, entity *openpgp.Entity) string {

	testenlist := make(openpgp.EntityList, 1)
	testenlist[0] = entity
	//fmt.Println("encryptedMessage: ", encryptedMessage)
	btest := bytes.NewBuffer([]byte(encryptedMessage))
	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(btest, testenlist, nil, nil)
	if err != nil {
		//return "", err
	}
	fmt.Println("after read:", md)
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		//return "", err
	}
	decStr := string(bytes)
	fmt.Println("decStr: ", decStr)

	return decStr
}
