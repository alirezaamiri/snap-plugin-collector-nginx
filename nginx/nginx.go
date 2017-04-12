/*
Copyright 2016 Staples, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nginx

import (
	"crypto/md5"
	"encoding/hex"
	//"encoding/json"
	"errors"
	"fmt"
	//"io/ioutil"
	"log"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"bufio"
	"github.com/intelsdi-x/snap-plugin-lib-go/v1/plugin"
)

const (
	numDotInIP  = 3
	httpTimeout = 5

	configServerURL = "nginx_server_url"
)

var (
	errorCfgParam    = errors.New("nginx_server_url config required. Check your config JSON file")
	errorBadServer   = errors.New("Failed to parse given nginx_server_url")
	errorRequestFail = errors.New("Request to nginx server failed")
	errorConfigRead  = errors.New("Config read error")
)

// NginxCollector type
type NginxCollector struct{}

// NewNginxCollector returns a NginxCollector struct
func NewNginxCollector() *NginxCollector {
	return &NginxCollector{}
}

//Convert unresolved ip address to md5
func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

//Get hostname based on server ip address of nginx metric
func getHostName(inData interface{}, hostName string) string {
	flag := false
	switch mtype := inData.(type) {
	case map[string]interface{}:
		hostName = mtype["server"].(string)
		//check for IPV4
		if strings.Count(hostName, ".") == numDotInIP {
			subStr := strings.Split(hostName, ":")
			hName, err := net.LookupAddr(subStr[0])
			if err == nil {
				hostName = strings.Join(hName, ".")
				flag = true
			}
		} else {
			if strings.Contains(hostName, "::") == true {
				subStr := strings.Split(hostName, "]")
				tStr := strings.TrimLeft(subStr[0], "[")
				hName, err := net.LookupAddr(tStr)
				if err == nil {
					hostName = strings.Join(hName, ".")
					flag = true
				}
			}
		}
	}
	if flag == false {
		//Default hostname with port will be encoded to md5
		hostName = fmt.Sprintf("host_id_%s", getMD5Hash(hostName))
	} else {
		hostName = fmt.Sprintf("host_id_%s", hostName)
	}
	hostName = strings.TrimRight(hostName, ".")
	replacer := strings.NewReplacer(".", "_", "/", "_", "\\", "_", ":", "_", "%", "_")
	hostName = replacer.Replace(hostName)
	return hostName
}

//Will ignore list of mertic
func checkIgnoreMetric(mkey string) bool {
	IgnoreChildMetric := "server"
	IgnoreMetric := ""
	ret := false
	if strings.EqualFold(IgnoreChildMetric, "nil") == false {
		subMetric := strings.Split(mkey, "/")
		if strings.Contains(IgnoreChildMetric, subMetric[len(subMetric)-1]) == true {
			ret = true
		}
	}
	if strings.EqualFold(IgnoreMetric, "nil") == false {
		if strings.Contains(IgnoreMetric, mkey) == true {
			ret = true
		}
	}

	return ret
}

//Namespace convert based on snap requirment
func getNamespace(mkey string) (ns plugin.Namespace) {
	rc := strings.Replace(mkey, ".", "-", -1)
	ss := strings.Split(rc, "/")
	ns = plugin.NewNamespace(ss...)
	return ns
}

//Flattern complex json struct metrics
func switchType(outMetric *[]plugin.Metric, mval interface{}, ak string) {
	switch mtype := mval.(type) {
	case bool:
		if checkIgnoreMetric(ak) == true {
			return
		}
		ns := getNamespace(ak)
		tmp := plugin.Metric{}
		tmp.Namespace = ns
		if mval.(bool) == false {
			tmp.Data = 0
		} else {
			tmp.Data = 1
		}
		tmp.Timestamp = time.Now()
		*outMetric = append(*outMetric, tmp)
	case int, int64, float64, string:
		if checkIgnoreMetric(ak) == true {
			return
		}
		ns := getNamespace(ak)
		tmp := plugin.Metric{}
		tmp.Namespace = ns
		tmp.Data = mval
		tmp.Timestamp = time.Now()
		*outMetric = append(*outMetric, tmp)
	case map[string]interface{}:
		parseMetrics(outMetric, mtype, ak)
	case []interface{}:
		parseArrMetrics(outMetric, mtype, ak)
	default:
		log.Println("In default missing type =", reflect.TypeOf(mval))
	}
	return
}

//Parse Arrary Metric Data
func parseArrMetrics(outMetric *[]plugin.Metric, inData []interface{}, parentKey string) {
	for mkey, mval := range inData {
		subMetric := strings.Split(parentKey, "/")
		if subMetric[len(subMetric)-1] == "peers" {
			hostName := getHostName(mval, strconv.Itoa(mkey))
			switchType(outMetric, mval, parentKey+"/"+hostName)
		} else {
			switchType(outMetric, mval, parentKey+"/"+strconv.Itoa(mkey))
		}
	}
	return
}

//Parse Metrics
func parseMetrics(outMetric *[]plugin.Metric, inData map[string]interface{}, parentKey string) {
	for mkey, mval := range inData {
		switchType(outMetric, mval, parentKey+"/"+mkey)
	}
	return
}

//Get nginx metric from Nginx application
func getMetrics(nginxServer string, metrics []string) (mList []plugin.Metric, err error) {
	httptimeout := time.Duration(httpTimeout) * time.Second
	client := &http.Client{
		Timeout: httptimeout,
	}
	resp, err1 := client.Get(nginxServer)
	if err1 != nil {
		return nil, err1
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errorRequestFail
	}

	/*body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		return nil, err2
	}

	jFmt := make(map[string]interface{})
	err = json.Unmarshal(body, &jFmt)
	if err != nil {
		return nil, err
	}*/
	

	r := bufio.NewReader(resp.Body)
	_, err = r.ReadString(':')
        if err != nil {
                return nil, err
        }
        line, err3 := r.ReadString('\n')
        if err3 != nil {
                return nil, err3
        }
        active, err4 := strconv.ParseUint(strings.TrimSpace(line), 10, 64)
        if err4 != nil {
                return nil, err4
        }


	// Server accepts handled requests
        _, err = r.ReadString('\n')
        if err != nil {
                return nil, err
        }
        line, err = r.ReadString('\n')
        if err != nil {
                return nil, err
        }
        data := strings.Fields(line)
        accepts, err5 := strconv.ParseUint(data[0], 10, 64)
        if err5 != nil {
                return nil, err5
        }

        handled, err6 := strconv.ParseUint(data[1], 10, 64)
        if err6 != nil {
                return nil, err6
        }
        requests, err7 := strconv.ParseUint(data[2], 10, 64)
        if err7 != nil {
                return nil, err
        }

        // Reading/Writing/Waiting
        line, err = r.ReadString('\n')
        if err != nil {
                return nil, err
        }
        data = strings.Fields(line)
        reading, err8 := strconv.ParseUint(data[1], 10, 64)
        if err8 != nil {
                return nil, err8
        }
        writing, err9 := strconv.ParseUint(data[3], 10, 64)
        if err9 != nil {
                return nil, err9
        }
        waiting, err10 := strconv.ParseUint(data[5], 10, 64)
        if err10 != nil {
                return nil, err10
        }
	
	fields := map[string]interface{}{
                "active":   int(active),
                "accepts":  int(accepts),
                "handled":  int(handled),
                "requests": int(requests),
                "reading":  int(reading),
                "writing":  int(writing),
                "waiting":  int(waiting),
        }
	pk := "gwdg" + "/" + "nginx"
	parseMetrics(&mList, fields, pk)

	return mList, nil
}

//CollectMetrics API definition
func (NginxCollector) CollectMetrics(mts []plugin.Metric) ([]plugin.Metric, error) {
	nginxServerURL, err := getConfigURL(mts[0].Config)
	if err != nil {
		return nil, errorBadServer
	}
	metricsList := make([]string, len(mts))

	for i, mt := range mts {
		metricsList[i] = "/" + strings.Join(mt.Namespace.Strings(), "/")
	}

	mList, err := getMetrics(nginxServerURL, metricsList)
	if err != nil {
		log.Println("Error in getMetrics =", err)
	}
	return mList, nil
}

// GetMetricTypes API definition
func (NginxCollector) GetMetricTypes(cfg plugin.Config) ([]plugin.Metric, error) {
	nginxServerURL, err := getConfigURL(cfg)
	if err != nil {
		return nil, errorConfigRead
	}

	mList, err := getMetrics(nginxServerURL, []string{})
	if err != nil {
		log.Println("Error in getMetrics =", err)
	}
	return mList, nil
}

//GetConfigPolicy API definition
func (NginxCollector) GetConfigPolicy() (plugin.ConfigPolicy, error) {
	cfg := plugin.NewConfigPolicy()
	cfg.AddNewStringRule([]string{"staples", "nginx"}, configServerURL, false)
	return *cfg, nil
}

// getConfigURL is just workaround for global config value
// being overwritten by default value from config policy
func getConfigURL(config plugin.Config) (string, error) {
	nginxServerURL, err := config.GetString(configServerURL)
	if err == plugin.ErrConfigNotFound {
		return "http://127.0.0.1/nginx_status", nil

	}
	return nginxServerURL, err
}
