/*-
 * Copyright (c) 2021-2022, Jörg Pernfuß
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type TLSServer struct {
	listener    net.Listener
	certificate tls.Certificate
	quit        chan interface{}
	exit        chan interface{}
	wg          sync.WaitGroup
	err         chan error
	remoteAddr  string
	client      *UDPClient
}

func NewTLSServer(addr, srvName, remote, caFile, certFile, keyFile string) (*TLSServer, error) {
	s := &TLSServer{
		quit:       make(chan interface{}),
		exit:       make(chan interface{}),
		err:        make(chan error),
		remoteAddr: remote,
	}

	caPool := x509.NewCertPool()
	if ca, err := ioutil.ReadFile(caFile); err != nil {
		return nil, fmt.Errorf("TLSServer/CA certificate: %w", err)
	} else {
		caPool.AppendCertsFromPEM(ca)
	}

	var err error
	if s.certificate, err = tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("TLSServer/CertificateKeypair: %w", err)
	}
	tlsConfig := &tls.Config{
		RootCAs:                  caPool,
		Time:                     time.Now().UTC,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP521},
		Certificates:             []tls.Certificate{s.certificate},
		ServerName:               srvName,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
		},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.NoClientCert,
	}
	tlsConfig.BuildNameToCertificate()
	if s.listener, err = tls.Listen(`tcp`, addr, tlsConfig); err != nil {
		return nil, fmt.Errorf("TLSServer/Listen: %w", err)
	}

	s.wg.Add(1)
	go s.serve()
	return s, nil
}

func (s *TLSServer) Err() chan error {
	return s.err
}

func (s *TLSServer) Exit() chan interface{} {
	return s.exit
}

func (s *TLSServer) serve() {
	defer s.wg.Done()
	log.Println(`TLSServer: start serving clients`)

	var err error
	s.client, err = NewUDPClient(s.remoteAddr)
	if err != nil {
		s.err <- err
		close(s.exit)
		return
	}

	connections := make(chan net.Conn)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

	acceptloop:
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.quit:
					break acceptloop
				default:
					s.err <- fmt.Errorf("TLSServer/Accept/fatal: %w", err)
					close(s.exit)
					break acceptloop
				}
			}
			connections <- conn
		}
	}()

serveloop:
	for {
		select {
		case conn := <-connections:
			s.wg.Add(1)
			go func() {
				log.Printf("TLSServer: accepted connection from: %s\n",
					conn.RemoteAddr().String(),
				)
				s.handleConnection(conn)
				s.wg.Done()
			}()
		case err := <-s.client.Err():
			s.err <- err
		case <-s.exit:
			log.Println(`TLSServer: goroutine indicated fatal error`)
			break serveloop
		case <-s.quit:
			log.Println(`TLSServer: received shutdown signal`)
			break serveloop
		}
	}

	ch := s.client.Stop()
drainloop:
	for {
		select {
		case e := <-ch:
			if err != nil {
				s.err <- e
				continue drainloop
			}
			break drainloop
		}
	}
}

func (s *TLSServer) Stop() chan error {
	go func(e chan error) {
		close(s.quit)
		s.listener.Close()
		s.wg.Wait()
		close(e)
	}(s.Err())
	return s.Err()
}

func (s *TLSServer) handleConnection(conn net.Conn) {
	defer conn.Close()

ReadLoop:
	for {
		select {
		case <-s.quit:
			break ReadLoop
		default:
			conn.SetDeadline(time.Now().Add(750 * time.Millisecond))

			scanner := bufio.NewScanner(conn)
			scanner.Split(s.split)
			// buffer size of the tlsclient sending the UDP packets
			buf := make([]byte, 8192+len(delim)+1, 8192+len(delim)+1)
			scanner.Buffer(buf, 8192+len(delim)) //max usage 1 byte below cap

			for scanner.Scan() {
				token := make([]byte, 8192+len(delim))
				i := copy(token, scanner.Bytes())
				// send via UDP, but discard if buffered channel is full
				go func() {
					select {
					case s.client.Input() <- token[:i]:
					default:
					}
				}()

				// refresh deadline after a read and s.quit has not
				// been closed yet
				select {
				case <-s.quit:
					log.Printf("TLSServer: forcing close on connection from: %s\n",
						conn.RemoteAddr().String(),
					)
					break ReadLoop
				default:
					conn.SetDeadline(time.Now().Add(750 * time.Millisecond))
				}
			}

			if err := scanner.Err(); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					// conn.Deadline triggered
					continue ReadLoop
				} else if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					// net package triggered timeout
					continue ReadLoop
				} else if err != io.EOF {
					s.err <- fmt.Errorf("TLSServer/Datastream/Split: %w", err)
				}
			}
			// scanner finished without error or timeout -> received EOF and
			// connection is closed
			break ReadLoop
		}
	}
	conn.Close()
}

func (s *TLSServer) split(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, delim); i >= 0 {
		return i + len(delim), data[0:i], nil
	}
	if atEOF {
		if i := bytes.Index(data, delim); i >= 0 {
			return i + len(delim), data[0:i], nil
		}
		// endmarker is missing
		return 0, nil, ErrIncomplete
	}
	return 0, nil, nil
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
