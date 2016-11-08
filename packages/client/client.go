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
	"net"
	"net/http"
	"net/url"
	"os"
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
	if err != nil {
		return
	}
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
	}
	fmt.Println("endpoints: ", c.endpoints)

	return
}

//GetHTTPTransport http transport for the cert and key
func (c *Client) GetHTTPTransport(certFilePath, keyFilePath string) (err error) {
	if certFilePath == "" || keyFilePath == "" {
		return errors.New("Require both cert and key path")
	}

	// Check if the cert and key files exists
	if _, err = os.Stat(certFilePath); os.IsNotExist(err) {
		return fmt.Errorf("Cert file %s does not exist", certFilePath)
	}

	if _, err = os.Stat(keyFilePath); os.IsNotExist(err) {
		return fmt.Errorf("Key file %s does not exist", keyFilePath)
	}

	fmt.Println("publicKeyTest start")
	tlsCert, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return
	}
	certx509, _ := ioutil.ReadFile(certFilePath)

	block, _ := pem.Decode([]byte(certx509))
	certTest, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
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
func NewClient(service, proto, domain, cert, key string) (err error) {
	c := &Client{}
	err = c.GetEndpoints(service, proto, domain)
	if err != nil {
		return
	}
	err = c.GetHTTPTransport(cert, key)
	if err != nil {
		return
	}
	cfg := client.Config{
		Endpoints: c.endpoints,
		Transport: c.httpTransport,
		// set timeout per request to fail fast when the target endpoint is unavailable
		HeaderTimeoutPerRequest: time.Second,
	}
	cli, err := client.New(cfg)
	if err != nil {
		return
	}
	kapi := client.NewKeysAPI(cli)
	resp, err := kapi.Get(context.Background(), "/TestEtcd/461046A0297D5848D5510BE07A37D03F6180BF17/Foo", nil)
	if err != nil {
		return
	}
	if resp != nil {
		// print common key info
		fmt.Printf("Get is done. Metadata is %q\n", resp)
		//fmt.Println("pgp value: ", resp.Node.Value)
		// print value
		value, err := DecryptValue(resp.Node.Value, key, c.entity)
		if err != nil {
			return err
		}
		fmt.Printf("%q key has %q value\n", resp.Node.Key, value)
	}

	return
}

// DecryptValue decrypts the pgp key using the entitylist
func DecryptValue(encryptedMessage string, privateKey string, entity *openpgp.Entity) (decStr string, err error) {

	testenlist := make(openpgp.EntityList, 1)
	testenlist[0] = entity
	btest := bytes.NewBuffer([]byte(encryptedMessage))
	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(btest, testenlist, nil, nil)
	if err != nil {
		return
	}
	fmt.Println("after read:", md)
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return
	}
	decStr = string(bytes)
	fmt.Println("decStr: ", decStr)

	return
}
