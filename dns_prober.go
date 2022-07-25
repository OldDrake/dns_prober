package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/miekg/dns"
)

const (
	user_name = "mdk"
	passwd    = "mdk199961"
	ip        = "127.0.0.1"
	port      = "3306"
	database  = "do53"
	table     = "scan_result"
	au_dns    = "159.75.200.247:53"
)

type Data struct {
	target   string
	response []string
	flag     bool
}

var epoch string
var db *sql.DB

func send_query(addr string) (*dns.Msg, error) {
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	domain := strings.Join([]string{timestamp, "-scan.dkeeper.top."}, "")

	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeA)
	m.RecursionDesired = true

	res, err := dns.Exchange(m, addr)
	return res, err
}

func initDB() error {
	// connect to mysql
	var err error
	path := strings.Join([]string{user_name, ":", passwd, "@tcp(", ip, ":", port, ")/", database, "?charset=utf8"}, "")
	db, err = sql.Open("mysql", path)
	if err != nil {
		fmt.Println("connect failed")
		return err
	}
	fmt.Println("connect success")
	db.SetConnMaxLifetime(100)
	db.SetMaxIdleConns(20)
	return nil
}

func retrieve_ip_sql(pool chan string) {
	cnt := 0

	//retrieve ip from mysql
	rows, err := db.Query("select max(epoch) from scan_result")
	if err != nil {
		panic(err)
	}
	rows.Next()
	rows.Scan(&epoch)
	cmd := strings.Join([]string{"select ip from scan_result where rcode = 0 and epoch = ", epoch}, "")
	rows, err = db.Query(cmd)
	defer rows.Close()
	if err == nil {
		fmt.Println("sending msg...")
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				fmt.Println(err)
				fmt.Println("retrieve error.")
				continue
			}
			pool <- ip
			cnt++
			if cnt%1000 == 0 {
				fmt.Println(cnt)
			}
		}
	} else {
		fmt.Println(err)
		fmt.Println("retrieve query error.")
	}
	close(pool)
	return
}

func store_data_sql(data_pool chan Data, wg *sync.WaitGroup) {
	rdns := make(map[string]int)
	wg.Add(1)
	for {
		if data, ok := <-data_pool; ok {
			dnstype := 0
			//fmt.Println(data.target)
			//fmt.Println(data.response)
			if data.flag == true {
				dnstype = 2
				for _, v := range data.response {
					if v == data.target {
						dnstype = 1
						continue
					}
					_, err := db.Exec("insert into forward_dns (forwarder, upstream, epoch) values (?,?,?)", data.target, v, epoch)
					if err != nil {
						panic(err)
						continue
					}
					if _, ok := rdns[v]; !ok {
						rdns[v] = 1
					}
				}
				if len(data.response) > 1 {
					if dnstype == 1 {
						dnstype = 3
					}
				}
			} else {
				if len(data.response) > 0 {
					dnstype = 5
					for _, v := range data.response {
						db.Exec("insert into nonstandard_dns (ip, record, epoch) values (?,?,?)", data.target, v, epoch)
					}
				}
			}
			db.Exec("insert into dns_type (ip, type, epoch) values (?,?,?)", data.target, dnstype, epoch)
		} else {
			break
		}
	}
	var data_list []string
	cmd := "insert ignore into dns_type (ip, type, epoch) values "
	for k, _ := range rdns {
		tmp := fmt.Sprintf("(\"%s\",%d,%s)", k, 4, epoch)
		data_list = append(data_list, tmp)
	}
	cmd = cmd + strings.Join(data_list, ",")
	for {
		_, err := db.Exec(cmd)
		if err != nil {
			//fmt.Println(err)
			//fmt.Println("insert error.")
			time.Sleep(1 * time.Second)
		} else {
			break
		}
	}
	wg.Done()
}

func retrieve_ip(pool chan string) {
	cnt := 0
	f, err := os.Open("data/noerr.txt")
	if err != nil {
		fmt.Println("cannot open file")
		return
	}
	defer f.Close()

	fmt.Println("sending msg ...")
	reader := bufio.NewReader(f)
	for {
		s, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		s = s[:(len(s) - 1)] //remove \n in linux | remove \r\n in windows
		pool <- s
		cnt++
		if cnt%1000 == 0 {
			fmt.Println(cnt)
		}
	}
	close(pool)
	return
}

func create_threads(ip_pool chan string, data_pool chan Data, wg1 *sync.WaitGroup, wg2 *sync.WaitGroup) {
	for i := 0; i < 120; i++ {
		go dns_query(ip_pool, data_pool, wg1)
	}
	for i := 0; i < 120; i++ {
		go store_data_sql(data_pool, wg2)
	}
	wg1.Wait()
	close(data_pool)
}

func active_probe(n int, addr string) Data {
	target_ip := addr[:len(addr)-3]
	data := Data{target_ip, nil, false}
	for i := 0; i < n; i++ {
		in, err := send_query(addr)
		if err == nil {
			if len(in.Answer) == 2 {
				if r, ok := in.Answer[0].(*dns.A); ok {
					if r.A.String() == "192.168.99.61" {
						data.flag = true
						if r2, ok2 := in.Answer[1].(*dns.A); ok2 {
							ip := r2.A.String()
							existed := false
							for _, v := range data.response {
								if v == ip {
									existed = true
									break
								}
							}
							if existed == false {
								data.response = append(data.response, ip)
							}
						}
					} else {
						ip1 := r.A.String()
						if r2, ok2 := in.Answer[1].(*dns.A); ok2 {
							ip2 := r2.A.String()
							if ip2 == "192.168.99.61" {
								data.flag = true
								existed := false
								for _, v := range data.response {
									if v == ip1 {
										existed = true
										break
									}
								}
								if existed == false {
									data.response = append(data.response, ip1)
								}
							}
						}
					}
				}
			} else if len(in.Answer) > 0 {
				if r, ok := in.Answer[0].(*dns.A); ok {
					ip := r.A.String()
					if ip != "192.168.99.61" {
						existed := false
						for _, v := range data.response {
							if v == ip {
								existed = true
								break
							}
						}
						if existed == false {
							data.response = append(data.response, ip)
						}
					}
				}
			}
		}
	}
	return data
}

func dns_query(pool chan string, data_pool chan Data, wg *sync.WaitGroup) {
	wg.Add(1)
	for {
		if s, ok := <-pool; ok {
			ip := []byte(s)
			port := []byte(":53")
			addr := string(append(ip, port...))
			data := active_probe(5, addr)
			if data.response != nil {
				data_pool <- data
			}
		} else {
			break
		}
	}
	wg.Done()
}

func main() {
	ip_pool := make(chan string, 500)
	data_pool := make(chan Data, 20)
	var probe_tasks sync.WaitGroup
	var store_tasks sync.WaitGroup
	//go retrieve_ip(ip_pool)
	if err := initDB(); err != nil {
		panic(err)
	}
	go retrieve_ip_sql(ip_pool)
	create_threads(ip_pool, data_pool, &probe_tasks, &store_tasks)
	store_tasks.Wait()
	db.Close()
	fmt.Println("All done!")
}
