//     Copyright (C) 2020, IrineSistiana
//
//     This file is part of mos-chinadns.
//
//     mosdns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mosdns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/sirupsen/logrus"
)

var (
	configPath  = flag.String("c", "config.json", "[path] load config from file")
	genConfigTo = flag.String("gen", "", "[path] generate a config template here")

	dir                 = flag.String("dir", "", "[path] change working directory to here")
	dirFollowExecutable = flag.Bool("dir2exe", false, "change working directory to the executable that started the current process")

	verbose = flag.Bool("v", false, "more log")
	quite   = flag.Bool("q", false, "no log")

	cpu = flag.Int("cpu", runtime.NumCPU(), "the maximum number of CPUs that can be executing simultaneously")
)

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(*cpu)

	logger := logrus.New()
	switch {
	case *quite:
		logger.SetLevel(logrus.ErrorLevel)
	case *verbose:
		logger.SetLevel(logrus.DebugLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}
	entry := logrus.NewEntry(logger)
	//gen config
	if len(*genConfigTo) != 0 {
		err := genJSONConfig(*genConfigTo)
		if err != nil {
			entry.Errorf("can not generate config template, %v", err)
		} else {
			entry.Print("config template generated")
		}
		return
	}

	// try to change working dir to os.Executable() or *dir
	var wd string
	if *dirFollowExecutable {
		ex, err := os.Executable()
		if err != nil {
			entry.Fatalf("get executable path: %v", err)
		}
		wd = filepath.Dir(ex)
	} else {
		if len(*dir) != 0 {
			wd = *dir
		}
	}
	if len(wd) != 0 {
		err := os.Chdir(wd)
		if err != nil {
			entry.Fatalf("changes the current working directory to %s: %v", wd, err)
		}
		entry.Infof("changes the current working directory to %s", wd)
	}

	//checking
	if len(*configPath) == 0 {
		entry.Fatal("need a config file")
	}

	c, err := loadJSONConfig(*configPath)
	if err != nil {
		entry.Fatalf("can not load config file, %v", err)
	}

	d, err := initDispather(c, entry)
	if err != nil {
		entry.Fatalf("init dispather: %v", err)
	}

	startServerExitWhenFailed := func(network string) {
		entry.Infof("%s server started", network)
		if err := d.ListenAndServe(network); err != nil {
			entry.Fatalf("%s server exited with err: %v", network, err)
		} else {
			entry.Infof("%s server exited", network)
			os.Exit(0)
		}
	}

	switch c.BindProtocol {
	case "all", "":
		go startServerExitWhenFailed("tcp")
		go startServerExitWhenFailed("udp")
	case "udp":
		go startServerExitWhenFailed("udp")
	case "tcp":
		go startServerExitWhenFailed("tcp")
	default:
		entry.Fatalf("init dispather: unknown bind protocol: %s", c.BindProtocol)
	}

	//wait signals
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	s := <-osSignals
	entry.Infof("exiting: signal: %v", s)
	os.Exit(0)
}
