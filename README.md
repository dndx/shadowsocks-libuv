shadowsocks-libuv
=================
[![Build Status](https://travis-ci.org/dndx/shadowsocks-libuv.png?branch=master)](https://travis-ci.org/dndx/shadowsocks-libuv)

shadowsocks is a lightweight tunnel proxy which can help you get through firewalls. 

protol made by [clowwindy](https://raw.github.com/clowwindy/), libuv port by [dndx](https://github.com/dndx)

This is only a **server**, it should works with any shadowsocks client. 

Current version: 0.1

This is an [Open Source](http://opensource.org/licenses/MIT) project and released under [The MIT License](http://opensource.org/licenses/MIT)

## Features
* Super fast and low resource consume (thanks to [libuv](https://github.com/joyent/libuv)), it can run very smoothly on almost any VPS. 
* Fully compatible to other port of shadowsocks. 

## Attention
This is an initial release and may not considered very stable, please open an issue if you encounter any bugs. Be sure to attach the error message so I can identify it. 

## How to Build
	$ git clone --recursive git@github.com:dndx/shadowsocks-libuv.git
	$ cd shadowsocks-libuv/
	$ vim config.h
	$ make
	$ ./server

Note that you need to rebuild it every time you modify config.h, just run `make` again and it will do rest of the work. 

Tested and confirmed to work on:

* Max OS X 10.8.2 x64 using clang 4.1
* CentOS 5.8 x86 using gcc 4.1.2

## Performance
I did not fully benchmark it yet, but accourding my usage on [TinyVZ](http://tinyvz.com/) (128M RAM and CentOS 5.8 x86). When watching YouTube 1080p vedio it use at most 3% of RAM and almost no CPU time. Which can be considered effective. 

## TODO List
* IPv6 Support !important
* RC4 Crypto Support
* Add Multi Port Support
* Client Implement
* …to be continued…