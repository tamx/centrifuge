package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type myCentrifuge struct {
	serverport string
	sslflag    bool
	httpflag   bool
}

var centrifuge map[string]map[string]myCentrifuge

func parseCentrifuge(param string) error {
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
		return errors.New("parameter error")
	} else if len(params) > 4 {
		return errors.New("parameter error")
	} else if len(params) == 4 {
		domain := params[0]
		tmp := myCentrifuge{params[2] + ":" + params[3],
			ssl, httpflag}
		if centrifuge[domain] == nil {
			centrifuge[domain] = map[string]myCentrifuge{}
		}
		centrifuge[domain][params[1]] = tmp
	} else if len(params) == 3 {
		tmp := myCentrifuge{params[1] + ":" + params[2],
			ssl, httpflag}
		centrifuge[""][params[0]] = tmp
	} else if len(params) == 2 {
		tmp := myCentrifuge{params[0] + ":" + params[1],
			ssl, httpflag}
		centrifuge[""][""] = tmp
	}
	return nil
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	centrifuge = map[string]map[string]myCentrifuge{}
	centrifuge[""] = map[string]myCentrifuge{}
	var hostnameArray arrayFlags

	port := flag.String("p", "0.0.0.0:443/ssl", "listen port")
	flag.Var(&hostnameArray, "n", "host name")
	flag.Parse()

	for _, param := range flag.Args() {
		if err := parseCentrifuge(param); err != nil {
			fmt.Println("Error: " + param)
			return
		}
	}

	ssl := false
	listenport := *port
	if strings.HasSuffix(listenport, "/ssl") {
		ssl = true
		listenport = listenport[0 : len(listenport)-4]
	}

	if ssl {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,                       // Let's Encryptの利用規約への同意
			HostPolicy: autocert.HostWhitelist(hostnameArray...), // ドメイン名
			Cache:      autocert.DirCache("certs"),               // 証明書などを保存するフォルダ
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

func SetKeepAlive(conn net.Conn) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("error: not *net.TCPConn")
	}
	// Set Keep-Alive
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return err
	}
	if err := tcpConn.SetKeepAlivePeriod(10 * time.Second); err != nil {
		return err
	}
	return nil
}

func handleToServer(header []byte,
	conn net.Conn, server net.Conn, httpflag bool) {
	defer conn.Close()
	defer server.Close()
	SetKeepAlive(conn)
	SetKeepAlive(server)
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
	domain := ""
	if sslConn, ok := conn.(*tls.Conn); ok {
		domain = sslConn.ConnectionState().ServerName
	}
	// fmt.Println(domain)
	choice := centrifuge[domain]
	if choice == nil {
		choice = centrifuge[""]
	}
	key := ""
	for k := range choice {
		if len(k) <= len(key) {
			continue
		}
		if strings.HasPrefix(message, k) {
			key = k
		}
	}
	// fmt.Println(key)
	value := choice[key].serverport
	sslflag := choice[key].sslflag
	httpflag := choice[key].httpflag
	// fmt.Println(key)
	// fmt.Println(value)
	if sslflag {
		config := &tls.Config{InsecureSkipVerify: true}
		server, err := tls.Dial("tcp", value, config)
		checkError(err)
		if err == nil {
			handleToServer(messageBuf[:messageLen],
				conn, server, httpflag)
		}
	} else {
		server, err := net.Dial("tcp", value)
		checkError(err)
		if err == nil {
			handleToServer(messageBuf[:messageLen],
				conn, server, httpflag)
		}
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: error: %s\n", err.Error())
	}
}
