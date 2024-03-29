package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

type myCentrifuge struct {
	serverport string
	sslflag    bool
	httpflag   bool
}

type myKey []string

func (k myKey) Len() int {
	return len(k)
}

func (k myKey) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}

func (k myKey) Less(i, j int) bool {
	if len(k[i]) == len(k[j]) {
		return k[i] > k[j]
	}
	return len(k[i]) > len(k[j])
}

var centrifuge map[string]myCentrifuge
var orderedKey myKey

func main() {
	centrifuge = make(map[string]myCentrifuge)

	port := flag.String("p", "0.0.0.0:443/ssl", "listen port")
	hostname := flag.String("n", "example.com", "host name")
	flag.Parse()

	for _, param := range flag.Args() {
		ssl := false
		if strings.HasSuffix(param, "/ssl") {
			ssl = true
			param = param[0 : len(param)-4]
		}
		httpflag := false
		if strings.HasSuffix(param, "/http") {
			httpflag = true
			param = param[0 : len(param)-5]
		}
		params := strings.Split(param, ":")
		if len(params) <= 1 {
			fmt.Println("Error: " + param)
			return
		} else if len(params) > 3 {
			fmt.Println("Error: " + param)
			return
		} else if len(params) == 3 {
			tmp := myCentrifuge{params[1] + ":" + params[2], ssl, httpflag}
			centrifuge[params[0]] = tmp
		} else if len(params) == 2 {
			tmp := myCentrifuge{params[0] + ":" + params[1], ssl, httpflag}
			centrifuge[""] = tmp
		}
	}
	orderedKey = myKey{}
	for key := range centrifuge {
		orderedKey = append(orderedKey, key)
	}
	sort.Sort(orderedKey)

	ssl := false
	listenport := *port
	if strings.HasSuffix(listenport, "/ssl") {
		ssl = true
		listenport = listenport[0 : len(listenport)-4]
	}

	if ssl {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,                // Let's Encryptの利用規約への同意
			HostPolicy: autocert.HostWhitelist(*hostname), // ドメイン名
			Cache:      autocert.DirCache("certs"),        // 証明書などを保存するフォルダ
		}

		// http-01 Challenge(ドメインの所有確認)、HTTPSへのリダイレクト用のサーバー
		challengeServer := &http.Server{
			Handler: certManager.HTTPHandler(nil),
			Addr:    ":10080",
		}
		go challengeServer.ListenAndServe()

		// config := &tls.Config{Certificates: []tls.Certificate{cer}}
		config := &tls.Config{
			GetCertificate: certManager.GetCertificate,
		}
		ln, err := tls.Listen("tcp", listenport, config)
		if err != nil {
			checkError(err)
			return
		}
		defer ln.Close()

		for {
			conn, err := ln.Accept()
			if err != nil {
				checkError(err)
				continue
			}
			go handleClient(conn)
		}
	} else {
		ln, err := net.Listen("tcp", listenport)
		if err != nil {
			checkError(err)
			return
		}
		defer ln.Close()

		for {
			conn, err := ln.Accept()
			if err != nil {
				checkError(err)
				continue
			}
			go handleClient(conn)
		}
	}
}

func handleToServer(header []byte,
	conn net.Conn, server net.Conn, httpflag bool) {
	defer conn.Close()
	defer server.Close()
	if httpflag {
		i := strings.Index(string(header), "\n") + 1
		server.Write(header[:i])
		address := conn.RemoteAddr().String()
		index := strings.Index(address, ":")
		address = address[:index]
		server.Write([]byte("X-Forwarded-For: " +
			address + "\r\n"))
		server.Write(header[i:])
	} else {
		server.Write(header)
	}

	ch := make(chan int)
	go func() {
		io.Copy(server, conn)
		ch <- 0
	}()
	go func() {
		io.Copy(conn, server)
		ch <- 0
	}()
	<-ch
	<-ch
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	messageBuf := make([]byte, 1024)
	messageLen, err := conn.Read(messageBuf)
	checkError(err)
	if err != nil {
		conn.Close()
		return
	}

	message := string(messageBuf[:messageLen])
	// fmt.Println(message)
	for _, key := range orderedKey {
		// fmt.Println(key)
		if strings.HasPrefix(message, key) {
			value := centrifuge[key].serverport
			sslflag := centrifuge[key].sslflag
			httpflag := centrifuge[key].httpflag
			// fmt.Println(key)
			// fmt.Println(value)
			if sslflag {
				config := &tls.Config{InsecureSkipVerify: true}
				server, err := tls.Dial("tcp", value, config)
				checkError(err)
				if err == nil {
					handleToServer(messageBuf[:messageLen], conn, server, httpflag)
				}
			} else {
				server, err := net.Dial("tcp", value)
				checkError(err)
				if err == nil {
					handleToServer(messageBuf[:messageLen], conn, server, httpflag)
				}
			}
			return
		}
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: error: %s\n", err.Error())
	}
}
