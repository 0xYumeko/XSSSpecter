package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/PuerkitoBio/goquery"
	. "github.com/logrusorgru/aurora"
)

func IsOnline() bool {
	_, err := http.Get("https://www.google.com")
	if err == nil {
		return true
	}
	fmt.Println(Cyan("[-] Interface has been disconnected from the network, please connect or set a connection "))
	return false
}
func processElement(index int, element *goquery.Selection) {
	href, exists := element.Attr("href")
	if exists {
		fmt.Println(href)
	}
}
func main() {
	uro := os.Args[1]
	IsOnline()
	resp, err := http.Get(uro)
	if err != nil {
		log.Fatal(err)
		fmt.Println("A error occured -> ", err)
	}
	if resp.StatusCode >= 400 {
		fmt.Println("[-] Server is not up or isnt a working direcotry now, try again later")
	} else {
		fmt.Println(Red(""))
	}
	time.Sleep(10 * time.Second)
	resp, err = http.Get(uro)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Response Status  -> ", resp.StatusCode, http.StatusText(resp.StatusCode))
	fmt.Println("[+] Date Of Request  -> ", resp.Header.Get("date"))
	fmt.Println("[+] Content-Encoding -> ", resp.Header.Get("content-encoding"))
	fmt.Println("[+] Content-Type     -> ", resp.Header.Get("content-type"))
	fmt.Println("[+] Connected-Server -> ", resp.Header.Get("server"))
	fmt.Println("[+] X-Frame-Options  -> ", resp.Header.Get("x-frame-options"))
	for k, v := range resp.Header {
		fmt.Print(Cyan("[+] -> " + k))
		fmt.Print(Red(" -> "))
		fmt.Println(v)
	}
	parsedURL, err := url.Parse(uro)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Scheme        --->  " + parsedURL.Scheme)
	fmt.Println("Hostname      --->  " + parsedURL.Host)
	fmt.Println("Path in URL   --->  " + parsedURL.Path)
	fmt.Println("Query Strings --->  " + parsedURL.RawQuery)
	fmt.Println("Fragments     --->  " + parsedURL.Fragment)
	queryMap := parsedURL.Query()
	fmt.Println(queryMap)
	response, err := http.Get(uro)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
}
