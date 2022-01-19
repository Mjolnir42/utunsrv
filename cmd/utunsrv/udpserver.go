/*-
 * Copyright (c) 2021-2022, Jörg Pernfuß
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type UDPServer struct {
	listener   *net.UDPConn
	quit       chan interface{}
	exit       chan interface{}
	wg         sync.WaitGroup
	err        chan error
	remoteAddr string
	caFile     string
}

func NewUDPServer(addr, remote, caFile string) (*UDPServer, error) {
	s := &UDPServer{
		quit:       make(chan interface{}),
		exit:       make(chan interface{}),
		err:        make(chan error),
		remoteAddr: remote,
		caFile:     caFile,
	}

	var err error
	var lUDPAddr *net.UDPAddr
	if lUDPAddr, err = net.ResolveUDPAddr(`udp`, addr); err != nil {
		return nil, fmt.Errorf("UDPServer/ResolveAddr: %w", err)
	}

	if s.listener, err = net.ListenUDP(`udp`, lUDPAddr); err != nil {
		return nil, fmt.Errorf("UDPServer/ListenUDP: %w", err)
	}
	log.Printf("UDPServer: listening on %s\n", addr)

	s.wg.Add(1)
	go s.serve()
	return s, nil
}

func (s *UDPServer) serve() {
	defer s.wg.Done()

	client, err := NewTLSClient(s.remoteAddr, s.caFile)
	if err != nil {
		s.err <- err
		close(s.exit)
		return
	}

	buf := make([]byte, 8192)
UDPDataLoop:
	for {
		select {
		case <-s.exit:
			log.Println(`UDPServer: goroutine indicated fatal error`)
			break UDPDataLoop
		case <-s.quit:
			log.Println(`UDPServer: received shutdown signal`)
			break UDPDataLoop
		case err := <-client.Err():
			s.err <- err
		default:
			s.listener.SetDeadline(time.Now().Add(750 * time.Millisecond))

			n, _, err := s.listener.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					// deadline triggered
					continue UDPDataLoop
				} else if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					// net package triggered timeout
					continue UDPDataLoop
				} else if err != io.EOF {
					s.err <- fmt.Errorf("UDPServer/ReadFromUDP/fatal: %w", err)
					close(s.exit)
					break UDPDataLoop
				}
			}

			if n == 0 {
				// no data read, either with io.EOF or without
				continue UDPDataLoop
			}

			// make a data copy in an exact sized []byte
			data := make([]byte, n)
			copy(data, buf)

			select {
			case client.Input() <- data:
			default:
				// discard if buffered channel is full
			}
		}
	}
	log.Println(`UDP|Data: stopping client`)
	ch := client.Stop()
drainloop:
	for {
		select {
		case e := <-ch:
			if e != nil {
				s.err <- e
				continue
			}
			// channel closed, read is nil
			break drainloop
		}
	}
	log.Println(`UDP|Data: serve() done`)
}

func (s *UDPServer) Err() chan error {
	return s.err
}

func (s *UDPServer) Exit() chan interface{} {
	return s.exit
}

func (s *UDPServer) Stop() chan error {
	go func(e chan error) {
		log.Println(`UDP|STOP: Closing quit indicator channel`)
		close(s.quit)
		log.Println(`UDP|STOP: closing listener`)
		s.listener.Close()
		log.Println(`UDP|STOP: waiting for waitgroup`)
		s.wg.Wait()
		log.Println(`UDP|STOP: closing error channel`)
		close(e)
		log.Println(`UDP|STOP: done`)
	}(s.err)
	return s.err
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
