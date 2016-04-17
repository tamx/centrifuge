package main

import (
        "crypto/tls"
        "flag"
        "fmt"
        "net"
        "os"
        "strings"
)

var centrifuge map[string]string
var sslflag map[string]bool

func main() {
        centrifuge = make(map[string]string)
        sslflag = make(map[string]bool)

        port := flag.String("p", "0.0.0.0:443/ssl", "listen port")
        certpath := flag.String("cert", "ssl/cert.pem", "path for cert.pem")
        keypath := flag.String("key", "ssl/newkey.pem", "path for newkey.pem")
        flag.Parse()

        for _, param := range flag.Args() {
                ssl := false
                if strings.HasSuffix(param, "/ssl") {
                        ssl = true
                        param = param[0 : len(param)-4]
                }
                params := strings.Split(param, ":")
                if len(params) <= 1 {
                        fmt.Println("Error: " + param)
                        return
                } else if len(params) > 3 {
                        fmt.Println("Error: " + param)
                        return
                } else if len(params) == 3 {
                        centrifuge[params[0]] = params[1] + ":" + params[2]
                        sslflag[params[0]] = ssl
                } else if len(params) == 2 {
                        centrifuge[""] = params[0] + ":" + params[1]
                        sslflag[""] = ssl
                }
        }
        ssl := false
        listenport := *port
        if strings.HasSuffix(listenport, "/ssl") {
                ssl = true
                listenport = listenport[0 : len(listenport)-4]
        }

        if ssl {
                cer, err := tls.LoadX509KeyPair(*certpath, *keypath)
                if err != nil {
                        checkError(err)
                        return
                }

                config := &tls.Config{Certificates: []tls.Certificate{cer}}
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

func pipe(reader net.Conn, writer net.Conn) {
        defer writer.Close()
        defer reader.Close()

        messageBuf := make([]byte, 1024)
        for {
                messageLen, err := reader.Read(messageBuf)
                if err != nil {
                        break
                }
                writer.Write(messageBuf[:messageLen])
        }
}

func handleToServer(header []byte, conn net.Conn, server net.Conn) {
        server.Write(header)

        go pipe(server, conn)
        go pipe(conn, server)
}

func handleClient(conn net.Conn) {
        messageBuf := make([]byte, 1024)
        messageLen, err := conn.Read(messageBuf)
        checkError(err)
        if err != nil {
                conn.Close()
                return
        }

        message := string(messageBuf[:messageLen])
        for key, value := range centrifuge {
                if key == "" {
                        continue
                }
                if strings.HasPrefix(message, key) {
                        if sslflag[key] {
                                config := &tls.Config{InsecureSkipVerify: true}
                                server, err := tls.Dial("tcp", value, config)
                                checkError(err)
                                handleToServer(messageBuf[:messageLen], conn, server)
                        } else {
                                server, err := net.Dial("tcp", value)
                                checkError(err)
                                handleToServer(messageBuf[:messageLen], conn, server)
                        }
                        return
                }
        }
        { // others(default)
                key := ""
                value := centrifuge[key]
                if sslflag[key] {
                        config := &tls.Config{InsecureSkipVerify: true}
                        server, err := tls.Dial("tcp", value, config)
                        checkError(err)
                        handleToServer(messageBuf[:messageLen], conn, server)
                } else {
                        server, err := net.Dial("tcp", value)
                        checkError(err)
                        handleToServer(messageBuf[:messageLen], conn, server)
                }
        }
}

func checkError(err error) {
        if err != nil {
                fmt.Fprintf(os.Stderr, "fatal: error: %s", err.Error())
        }
}
