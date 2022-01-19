/*-
 * Copyright (c) 2021-2022, Jörg Pernfuß
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type UDPClient struct {
	inqueue    chan []byte
	quit       chan interface{}
	err        chan error
	wg         sync.WaitGroup
	remoteAddr string
	UDPAddr    *net.UDPAddr
	UDPConn    *net.UDPConn
}

func NewUDPClient(remote string) (*UDPClient, error) {
	c := &UDPClient{
		inqueue:    make(chan []byte, 8192),
		quit:       make(chan interface{}),
		err:        make(chan error),
		remoteAddr: remote,
	}

	var err error
	if c.UDPAddr, err = net.ResolveUDPAddr(`udp`, c.remoteAddr); err != nil {
		return nil, fmt.Errorf("UDPClient/ResolveAddr: %w", err)
	}
	if c.UDPConn, err = net.DialUDP(`udp`, nil, c.UDPAddr); err != nil {
		return nil, fmt.Errorf("UDPClient/Connect: %w", err)
	}

	c.wg.Add(1)
	go c.run()
	return c, nil
}

func (c *UDPClient) Stop() chan error {
	go func(e chan error) {
		close(c.quit)
		c.wg.Wait()
		close(e)
	}(c.err)
	return c.err
}

func (c *UDPClient) Err() chan error {
	return c.err
}

func (c *UDPClient) Input() chan []byte {
	return c.inqueue
}

func (c *UDPClient) run() {
	defer c.wg.Done()

runloop:
	for {
		select {
		case <-c.quit:
			log.Println("UDPClient: received shutdown signal")
			break runloop

		case msg := <-c.inqueue:
		retryonerror:
			n, err := c.UDPConn.Write(msg)
			c.wg.Add(1)
			go func(e error) {
				defer c.wg.Done()
				if e != nil {
					c.err <- fmt.Errorf("UDPClient/Write: %w", e)
				}
			}(err)

		redial:
			if n != len(msg) {
				log.Println("UDPClient: reconnecting after error....")
				// check if quit signal arrives during redial
				select {
				case <-c.quit:
					break runloop
				default:
				}
				time.Sleep(250 * time.Millisecond)

				// re-resolve UDP address
				if c.UDPAddr, err = net.ResolveUDPAddr(
					`udp`, c.remoteAddr,
				); err != nil {
					c.wg.Add(1)
					go func(e error) {
						defer c.wg.Done()
						if err != nil {
							c.err <- fmt.Errorf("UDPClient/ResolveAddr: %w", e)
						}
					}(err)
					goto redial
				}
				// re-dial UDP connection
				if c.UDPConn, err = net.DialUDP(
					`udp`, nil, c.UDPAddr,
				); err != nil {
					c.wg.Add(1)
					go func(e error) {
						defer c.wg.Done()
						if err != nil {
							c.err <- fmt.Errorf("UDPClient/Dial: %w", e)
						}
					}(err)
					goto redial
				}

				// retry sending current msg
				goto retryonerror
			}
		}
	}
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
