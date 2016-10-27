package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
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
	"golang.org/x/net/context"
)

// Client has all the information required to connect to etcd and retrieve the key value store
type Client struct {
	endpoints     []string
	httpTransport *http.Transport
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
	tlsCert, err := tls.LoadX509KeyPair(cert, key)
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
	// create a new key /foo with the value "bar"
	// _, err = kapi.Create(context.Background(), "/foo", "bar")
	// if err != nil {
	// 	// handle error
	// }
	log.Print("Getting '/foo' key value")
	resp, err := kapi.Get(context.Background(), "/JavaGenericWorker/461046A0297D5848D5510BE07A37D03F6180BF17/host", nil)
	if err != nil {
		log.Fatal(err)
	} else {
		// print common key info
		fmt.Printf("Get is done. Metadata is %q\n", resp)
		fmt.Println("pgp value: ", resp.Node.Value)
		// print value
		fmt.Printf("%q key has %q value\n", resp.Node.Key, DecryptValue(resp.Node.Value, key))
	}
}

// DecryptValue does...
func DecryptValue(encryptedMessage string, privateKey string) string {
	const privateKey1 = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

lQH+BFLHbYYBBADCjgKHmPmwBxI3c3DPVoSdu0+EJl/EsS2HEaN63dnLkGsMAs+4
32wsywmMrzKqCL40sbhJVYBcfe0chL+cry4O54DX7+gA0ZSVzFUN2EGocnkaHzyS
fuUtBdCTmoWZZAGFiBwlIS7aE/86SOyHksFo8LRC9W/GIWQS2PbcadvUywARAQAB
/gMDApJxOwcsfChBYCCmhOAvotKdYcy7nuG7dyGDBlpclLJtH/PaakKSE33NtEj4
1fyixQOdwApxvuQ2P0VX3pie/De1KpbeqXfnPLsmsXQwrRPOo38T5zeJ5ToWUGDC
Oia69ep3kmHbAW41EBH/uk/nMM91QUdl4mkYsc3dhVOXbmf0xyRoP/Afqha4UhdZ
0XKlIZP1a5+3NF/Q6dAVG0+FlO5Hcai8n98jW0id8Yf6zI+1gFGvYYKhlifkdJeK
Nf4YEvOXALEvaQqkcJOxEca+BmqsgCIFctJe9Bahx97Ep5hP7AH0aBmtZfmGmZwB
GYoevUtKa4ASVmK8RaddBvIjcrWsoAsYMpDGYaE0fcdtxsBf3uT1Q8IMsT+ZRjjV
TfvJ8aW14ZrLI98KdtXaOPZs91mML+3iw1c/1O/IEJfwxrUni2p/fDmCYU9eHR3u
Q0PwVR0MCUHI1fGuUoetW2gYIxfklvBtEFWW1BD6fCpCtERHb2xhbmcgVGVzdCAo
UHJpdmF0ZSBrZXkgcGFzc3dvcmQgaXMgJ2dvbGFuZycpIDxnb2xhbmd0ZXN0QHRl
c3QuY29tPoi4BBMBAgAiBQJSx22GAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIX
gAAKCRBVSiCHf5i7zqKJA/sFUM2TfL2VZKWC7E1N1wwZctB9Bf77SeAPSVpGCZ0c
iUYIFdwwGowKtjoDrsbYgPp+UGOyYMD6tGzWKaJrQQoDyaQqVVRhbNXB7Jz7JT2a
qKHD1t7cx5FfUzDMBNou3TOWHomDXyQGDAULAZnjaOj8/pDe6poxyBluSjMJUzfD
pp0B/gRSx22GAQQArUMDqkGng9Cppk73UBWBd7jhhbtk0eaRQh/goUHhKJerZ4LM
Q21IKyIX+GQbscDpccpXMI6eThXxrL+D8G4cNb4ewvT0zc20+T91ztgT9A/4Vifc
EPQCErTqY/oZphAzZM1p6sRenc22e42iT0Iibd5gCs2wnSNeUzybDcuQi2EAEQEA
Af4DAwKScTsHLHwoQWCYayWqio8purPTonYogZSN3QwaheS2Y0NE7skdLOvP97vi
Rh7BktS6Dkgu0T3D39+q0O6ZO7XErvTVoas1F0HXzId4tiIicmx4tYNyWI4NrSO7
6TQPz/bQe8ZN+plG5cgZowts6g6RSfQxoW21LrP8Lh+OEdcYwWf7BTukAYmD3oq9
RxdfYI7hnbVGFdOqQUQNcxZkbdrsF9ITjQb/KRln5/99E1Kp1D45VpPOs7NT3orA
mnfSslJXVNm1uK6FDBX2iUe3JaAmgh+RLGXQXRZKJW4DGDTyYdwR4hO8cYix2+8z
+XuwdVDPKBnzKn190m6xpdLyvKfj1BQhX14NShPQZ3QJiMU0k4Js23XSsWs9NSxI
FjjE9/mOFVUH25KN+X7rzBPo2S0pMQLqyQxSLIdI2LPDxzlknctT6OoBPKPJjb7S
Lt5GhIA5Cz+cohfX6LePG4FkvwU32tTRBz5YNhFBizmS+YifBBgBAgAJBQJSx22G
AhsMAAoJEFVKIId/mLvOulED/2uUh/qjOT468XoK6Xt837w45JQPpLqiGH9KJgqF
rUxJMw1bIE2G606OY6hCgeE+YC8qny29hQtXhKIquUI/0A1qK3aCZhwqyqT+QjvF
6Xi0i/HrgQwCyBopY3uGndMbvthxU0KO0d6seMZltHDr8YaU1JvDwNFDQVuw+Rqy
57ET
=nvLl
-----END PGP PRIVATE KEY BLOCK-----`
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(privateKey1))
	if err != nil {
		log.Fatal(err)
	}
	entity := entityList[0]
	fmt.Println("Private key from armored string:", entity.Identities)

	// Decrypt armor encrypted message using private key
	// decbuf := bytes.NewBuffer([]byte(encryptedMessage))
	// result, err := armor.Decode(decbuf)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		//return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		//return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		//return "", err
	}
	decStr := string(bytes)
	fmt.Println("decStr: ", decStr)

	return decStr
}
