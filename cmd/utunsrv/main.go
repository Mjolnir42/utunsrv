/*-
 * Copyright (c) 2021-2022, Jörg Pernfuß
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Server interface {
	Err() chan error
	Exit() chan interface{}
	Stop() chan error
}

type Config struct {
	mode        string
	listenAddr  string
	forwardAddr string
	srvName     string
	caFile      string
	certFile    string
	keyFile     string
}

var ErrIncomplete = errors.New("Incomplete data with missing marker")

var delim = []byte{
	0b_1010_1010,
	0b_0000_0000,
	0b_0101_0101,
	0b_0000_0000,
	0b_0000_0000,
	0b_1101_1001,
	0b_0000_0000,
	0b_1001_1011,
}

func main() {
	flagListenTLS := flag.String("tlssrv", "", "host:port to listen with TLS")
	flagListenUDP := flag.String("udpsrv", "", "host:port to listen with UDP")
	flagRemote := flag.String("remote", "", "host:port to forward to")
	flagSrvName := flag.String("name", "", "servername presented via TLS")
	flagCA := flag.String("ca", "", "CA certificate file")
	flagCert := flag.String("tlscert", "", "TLS server certificate file")
	flagKey := flag.String("tlskey", "", "TLS server key file")
	flag.Parse()

	switch {
	case *flagRemote == ``:
		fallthrough
	case *flagListenTLS == `` && *flagListenUDP == ``:
		fallthrough
	case *flagListenTLS != `` && *flagListenUDP != ``:
		flag.PrintDefaults()
		os.Exit(1)
	}

	conf := Config{
		forwardAddr: *flagRemote,
		srvName:     *flagSrvName,
		caFile:      *flagCA,
		certFile:    *flagCert,
		keyFile:     *flagKey,
	}
	switch {
	case *flagListenTLS != ``:
		conf.mode = `TLS2UDP`
		conf.listenAddr = *flagListenTLS
	case *flagListenUDP != ``:
		conf.mode = `UDP2TLS`
		conf.listenAddr = *flagListenUDP
	}

	if err := run(conf); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(conf Config) error {
	var (
		srv   Server
		err   error
		drain chan error
	)

	switch conf.mode {
	case `UDP2TLS`:
		srv, err = NewUDPServer(
			conf.listenAddr,
			conf.forwardAddr,
			conf.caFile,
		)
	case `TLS2UDP`:
		srv, err = NewTLSServer(
			conf.listenAddr,
			conf.srvName,
			conf.forwardAddr,
			conf.caFile,
			conf.certFile,
			conf.keyFile,
		)
	}

	if err != nil {
		return err
	}

	cancel := make(chan os.Signal, 1)
	signal.Notify(cancel, os.Interrupt, syscall.SIGTERM)

runloop:
	for {
		select {
		case <-cancel:
			log.Println("untunsrv/main: received shutdown signal")
			drain = srv.Stop()
			break runloop
		case <-srv.Exit():
			log.Println("untunsrv/main: server process died")
			break runloop
		case err := <-srv.Err():
			log.Println(err)
		}
	}

	log.Println("untunsrv/main: flushing pending errors")
graceful:
	for {
		select {
		case <-time.After(time.Second * 15):
			log.Println("utunsrv/main: breaking graceful shutdown after 15s")
			break graceful
		case err := <-drain:
			if err != nil {
				log.Println(err)
				continue graceful
			}
			break graceful
		}
	}

	return nil
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
