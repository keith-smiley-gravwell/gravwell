/*************************************************************************
 * Copyright 2021 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package processors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gravwell/gravwell/v3/ingest/config"
	"github.com/gravwell/gravwell/v3/ingest/entry"
)

const (
	CorelightProcessor = `corelight`
)

var (
	defaultTag    string
	defaultPrefix = "zeek"
)

type CorelightConfig struct {
	// Prefix specifies the prefix for corelight logs. Each log type name will
	// be appended to the prefix to create a tag; thus if Prefix="zeek",
	// conn logs will be ingested to the 'zeekconn' tag, dhcp logs to 'zeekdhcp',
	// and so on.
	Prefix string
}

// A Corelight processor takes JSON-formatted Corelight logs and reformats
// them as TSV, matching the standard Zeek log types.
type Corelight struct {
	nocloser
	tg        Tagger
	tagFields map[string][]string
	tags      map[string]entry.EntryTag
	CorelightConfig
}

func CorelightLoadConfig(vc *config.VariableConfig) (c CorelightConfig, err error) {
	if err = vc.MapTo(&c); err != nil {
		return
	}
	if c.Prefix == `` {
		c.Prefix = defaultPrefix
	}
	return
}

func NewCorelight(cfg CorelightConfig, tagger Tagger) (*Corelight, error) {
	rr := &Corelight{
		CorelightConfig: cfg,
		tg:              tagger,
	}
	if err := rr.init(cfg, tagger); err != nil {
		return nil, err
	}
	return rr, nil
}

func (c *Corelight) Config(v interface{}, tagger Tagger) (err error) {
	if v == nil {
		err = ErrNilConfig
	} else if cfg, ok := v.(CorelightConfig); ok {
		err = c.init(cfg, tagger)
	} else {
		err = fmt.Errorf("Invalid configuration, unknown type type %T", v)
	}
	return
}

func (c *Corelight) init(cfg CorelightConfig, tagger Tagger) (err error) {
	if c.Prefix == "" {
		c.Prefix = defaultPrefix
	}
	c.tagFields = make(map[string][]string, len(tagHeaders))
	c.tags = make(map[string]entry.EntryTag)
	var k, v string
	for k, v = range tagHeaders {
		tagName := c.Prefix + k
		c.tagFields[tagName] = strings.Split(v, ",")
		if tv, err := c.tg.NegotiateTag(tagName); err != nil {
			return err
		} else {
			c.tags[tagName] = tv
		}
	}

	return
}

func (c *Corelight) Process(ents []*entry.Entry) ([]*entry.Entry, error) {
	if len(ents) == 0 {
		return ents, nil
	}
	for _, ent := range ents {
		if ent == nil || len(ent.Data) == 0 {
			continue
		} else if tag, ts, line := c.processLine(ent.Data); tag != defaultTag {
			// If processLine comes up with a different tag, it means it parsed JSON into
			// TSV, so let's rewrite the entry.
			if tv, ok := c.tags[tag]; ok {
				ent.Tag = tv
				ent.TS = entry.FromStandard(ts)
				ent.Data = line
			}
		}
	}
	return ents, nil
}

// processLine attempts to parse out the corelight JSON, figure out
// the log type (conn, dns, dhcp, weird, etc.), and convert the entry to TSV format.
// If it succeeds, it returns the destination tag, a new timestamp, and the log entry in TSV format
func (c *Corelight) processLine(s []byte) (tag string, ts time.Time, line []byte) {
	mp := map[string]interface{}{}
	line = s
	if idx := bytes.IndexByte(line, '{'); idx == -1 {
		tag = defaultTag
		return
	} else {
		line = line[idx:]
	}
	if err := json.Unmarshal(line, &mp); err != nil {
		tag = defaultTag
		return
	}
	tag, ts, line = c.process(mp, line)
	return
}

func (c *Corelight) process(mp map[string]interface{}, og []byte) (tag string, ts time.Time, line []byte) {
	var ok bool
	var headers []string
	if len(mp) == 0 {
		tag = defaultTag
		line = og
	} else if tag, ts, ok = c.getTagTs(mp); !ok {
		tag = defaultTag
		line = og
	} else if headers, ok = c.tagFields[tag]; !ok {
		tag = defaultTag
		line = og
	} else if line, ok = emitLine(ts, headers, mp); !ok {
		tag = defaultTag
		line = og
	}

	return
}

func (c *Corelight) getTagTs(mp map[string]interface{}) (tag string, ts time.Time, ok bool) {
	var tagv interface{}
	var tsv interface{}
	var tss string
	var tagval string
	var err error
	if tagv, ok = mp["_path"]; !ok {
		return
	} else if tsv, ok = mp["ts"]; !ok {
		return
	} else if tagval, ok = tagv.(string); !ok {
		return
	} else if tss, ok = tsv.(string); !ok {
		return
	} else if ts, err = time.Parse(time.RFC3339Nano, tss); err != nil {
		ok = false
	} else {
		tag = c.Prefix + tagval
	}
	return
}

func emitLine(ts time.Time, headers []string, mp map[string]interface{}) (line []byte, ok bool) {
	bb := bytes.NewBuffer(nil)
	var f64 float64
	fmt.Fprintf(bb, "%.6f", float64(ts.UnixNano())/1000000000.0)
	for _, h := range headers[1:] { //always skip the TS
		if v, ok := mp[h]; ok {
			if f64, ok = v.(float64); ok {
				if _, fractional := math.Modf(f64); fractional == 0 {
					fmt.Fprintf(bb, "\t%d", int(f64))
				} else {
					fmt.Fprintf(bb, "\t%.5f", f64)
				}
			} else {
				fmt.Fprintf(bb, "\t%v", v)
			}
		} else {
			fmt.Fprintf(bb, "\t-")
		}
	}
	line, ok = bb.Bytes(), true
	return
}

var tagHeaders = map[string]string{
	"conn":        "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,service,duration,id.orig_ip_bytes,id.resp_ip_bytes,conn_state,local_orig,local_resp,missed_bytes,history,id.orig_pkts,id.orig_ip_bytes,id.resp_pkts,id.resp_ip_bytes,tunnel_parents,vlan",
	"dhcp":        "ts,uids,client_addr,server_addr,mac,host_name,client_fqdn,domain,requested_addr,assigned_addr,lease_time,client_message,server_message,msg_types,duration",
	"dns":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,trans_id,rtt,query,qclass,qclass_name,qtype,qtype_name,rcode,rcode_name,AA,TC,RD,RA,Z,answers,TTLs,rejected",
	"files":       "ts,fuid,tx_hosts,rx_hosts,conn_uids,source,depth,analyzers,mime_type,filename,duration,local_orig,is_orig,seen_bytes,total_bytes,missing_bytes,overflow_bytes,timedout,parent_fuid,md5,sha1,sha256,extracted,extracted_cutoff,extracted_size",
	"http":        "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,trans_depth,method,host,uri,referrer,version,user_agent,id.origin,request_body_len,id.response_body_len,status_code,status_msg,info_code,info_msg,tags,username,password,proxied,id.orig_fuids,id.orig_filenames,id.orig_mime_types,id.resp_fuids,id.resp_filenames,id.resp_mime_types",
	"ssl":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,version,cipher,curve,server_name,resumed,last_alert,next_protocol,established,cert_chain_fuids,client_cert_chain_fuids,subject,issuer,client_subject,client_issuer,validation_status",
	"weird":       "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,name,addl,notice,peer",
	"x509":        "ts,uid,version,serial,subject,issuer,not_valid_before,not_valid_after,key_alg,sig_alg,key_type,key_length,exponent,curve,dns,uri,email,ip,ca,path_len",
	"ssh":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,version,auth_success,auth_attempts,direction,client,server,cipher_alg,mac_alg,compression_alg,kex_alg,host_key_alg,host_key,inferences",
	"sip":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,trans_depth,method,uri,date,request_fromrequest_to,id.response_from,id.response_to,reply_to,call_id,seq,subject,request_path,id.response_path,user_agent,status_code,status_msg,warning,request_body_len,id.response_body_len,content_type",
	"dpd":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,analyzer,failure_reason,packet_segment",
	"snmp":        "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,duration,version,community,get_requests,get_bulk_requests,get_responses,set_requests,display_string,up_since",
	"smtp":        "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,trans_depth,helo,mailfrom",
	"pe":          "ts,uid,machine,compile_ts,os,subsystem,is_exe,is_64bit,uses_aslr,uses_dep",
	"tunnel":      "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,tunnel_type,action",
	"socks":       "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,version,user,password,status,request,request_host,request_name,request_port,bound_host,bound_name",
	"software":    "ts,host,host_port,software_type,name,major,minor,minor2,minor3,addl,unparsed_version",
	"syslog":      "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,facility,severity,message",
	"rfb":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,client_major_version,client_minor_version,server_major_version,server_minor_version,authentication_method,auth,share_flag,desktop_name,width,height",
	"radius":      "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,username,mac,remote_ip,connect_info,result,logged",
	"rdp":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,cookie,result,security_protocol,client_build,client_name,client_dig_product_id,desktop_width,desktop_height,requested_color_depth,cert_type,cert_count,cert_permanent,encryption_level,encryption_method",
	"ftp":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,user,password,command,arg,mime_type,file_size,reply_code,reply_msg,data_channel.passive,data_channel.orig_h,data_channel.resp_h,data_channel.resp_p,fuid",
	"intel":       "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,indicator,indicator_type,seen_where,seen_node,matched,sources,fuid,file_mime_type,file_desc",
	"irc":         "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,nick,user,command,value,additional_info,dcc_file_name,dcc_file_size,dcc_mime_type,fuid",
	"kerberos":    "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,request_type,client,service,success,error_msg,from,till,cipher,forwardable,renewable,client_cert,client_cert_fuid,server_cert_subject,server_cert_fuid",
	"mysql":       "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,cmd,arg,success,rows,id.response",
	"modbus":      "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,func,exception",
	"notice":      "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,fuid,mime,desc,proto,note,msg,sub,src,dst,p,n,peer_descr,actions,suppress_for,dropped,destination_country_code,destination_region,destination_city,destination_latitude,destination_longitude",
	"signature":   "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,note,sig_id,event_msg,sub_msg,sig_count,host_count",
	"smb_mapping": "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,path,service,native_file_system,share_type",
	"smb_files":   "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,fuid,action,path,name,size,prev_name,modified,accessed,created,changed",
	"zeekdnp3":    "ts,uid,id,fc_request,fc_reply,iin",
}
