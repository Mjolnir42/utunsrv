/*-
 * Copyright (c) 2021-2022, Jörg Pernfuß
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type ping struct{}

type TLSClient struct {
	inqueue    chan []byte
	ping       chan ping
	quit       chan interface{}
	wg         sync.WaitGroup
	err        chan error
	remoteAddr string
	conf       *tls.Config
	conn       *tls.Conn
	connected  bool
}

func NewTLSClient(remote, caFile string) (*TLSClient, error) {
	c := &TLSClient{
		inqueue:    make(chan []byte, 8192),
		ping:       make(chan ping),
		quit:       make(chan interface{}),
		err:        make(chan error),
		remoteAddr: remote,
		connected:  false,
	}

	caPool := x509.NewCertPool()
	if ca, err := ioutil.ReadFile(caFile); err != nil {
		return nil, fmt.Errorf("TLSClient/CA certificate: %w", err)
	} else {
		caPool.AppendCertsFromPEM(ca)
	}

	c.conf = &tls.Config{
		RootCAs:          caPool,
		Time:             time.Now().UTC,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP521},
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
		},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ClientAuth:         tls.NoClientCert,
		InsecureSkipVerify: false,
	}
	c.conf.BuildNameToCertificate()

	c.wg.Add(1)
	go c.run()
	return c, nil
}

func (c *TLSClient) Stop() chan error {
	go func(e chan error) {
		close(c.quit)
		c.wg.Wait()
		close(e)
	}(c.err)
	return c.err
}

func (c *TLSClient) Err() chan error {
	return c.err
}

func (c *TLSClient) Input() chan []byte {
	return c.inqueue
}

func (c *TLSClient) run() {
	defer c.wg.Done()
	buf := make([]byte, 8192+len(delim))

	c.wg.Add(1)
	go c.Reconnect()

dataloop:
	for {
		select {
		case <-c.quit:
			log.Println(`TLSClient: shutdown signal received`)
			if c.conn != nil {
				// might be before first established connection
				c.conn.Close()
			}
			break dataloop
		case <-c.ping:
			continue dataloop
		case msg := <-c.inqueue:
			if !c.connected {
				select {
				case c.inqueue <- msg:
				default:
					// discard data while not connected and buffer is full
				}
				time.Sleep(125 * time.Millisecond)
				continue dataloop
			}
			copy(buf, msg)
			copy(buf[len(msg):], delim)

			if n, err := c.conn.Write(
				buf[:len(msg)+len(delim)],
			); err != nil {
				c.err <- fmt.Errorf("TLSClient/Write: %w", err)
				c.connected = false
				c.conn.Close()
				select {
				case c.inqueue <- msg:
				default:
					// discard data while if buffer is full
				}
			} else if n != len(msg)+len(delim) {
				c.connected = false
				c.conn.Close()
			}
		}
	}
}

func (c *TLSClient) Reconnect() {
	defer c.wg.Done()

	select {
	case <-c.quit:
		return
	default:
	}

	if c.conn != nil {
		c.conn.Close()
	}

connectloop:
	for ok := true; ok; ok = (c.connected == false) {
		dialer := &net.Dialer{
			Timeout:   750 * time.Millisecond,
			KeepAlive: 20 * time.Second,
		}
		var err error
		c.conn, err = tls.DialWithDialer(dialer, `tcp`, c.remoteAddr, c.conf)
		if err != nil {
			c.err <- fmt.Errorf("TLSClient/Reconnect: %w", err)
			time.Sleep(time.Second)
			select {
			case <-c.quit:
				return
			default:
				continue connectloop
			}
		}
		log.Printf("TLSClient: connected to %s\n", c.remoteAddr)
		break connectloop
	}

	c.connected = true
	c.ping <- ping{}

	c.wg.Add(1)
	go func() {
		readbuf := make([]byte, 512)

	detectloop:
		for {
			if err := c.conn.SetReadDeadline(
				time.Now().Add(250 * time.Millisecond),
			); err != nil {
				c.err <- fmt.Errorf("TLSClient/Reconnect: %w", err)
				c.connected = false
				c.conn.Close()
				break detectloop
			}
			if _, err := c.conn.Read(readbuf); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					c.conn.SetReadDeadline(time.Time{})
				} else {
					c.err <- fmt.Errorf("TLSClient/Reconnect: %w", err)
					c.connected = false
					c.conn.Close()
					break detectloop
				}
			}
		}
		select {
		case <-c.quit:
			// intentional noop
		default:
			log.Printf("TLSClient: reconnecting to %s\n", c.remoteAddr)
			c.wg.Add(1)
			c.Reconnect()
		}
		c.wg.Done()
	}()
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
