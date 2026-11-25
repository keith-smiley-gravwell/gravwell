/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// jsonObject writes an ordered JSON object.
type jsonObject struct {
	bb    *bytes.Buffer
	first bool
	err   error
}

func newObject(bb *bytes.Buffer) *jsonObject {
	bb.WriteByte('{')
	return &jsonObject{bb: bb, first: true}
}

func (o *jsonObject) key(k string) {
	if !o.first {
		o.bb.WriteByte(',')
	}
	o.first = false
	writeJSONString(o.bb, k)
	o.bb.WriteByte(':')
}

func (o *jsonObject) str(k, v string) {
	o.key(k)
	writeJSONString(o.bb, v)
}

func (o *jsonObject) strOmit(k, v string) {
	if v != `` {
		o.str(k, v)
	}
}

func (o *jsonObject) uint(k string, v uint64) {
	o.key(k)
	o.bb.WriteString(strconv.FormatUint(v, 10))
}

func (o *jsonObject) value(k string, v any) {
	o.key(k)
	if err := writeValue(o.bb, v); err != nil && o.err == nil {
		o.err = err
	}
}

func (o *jsonObject) close() error {
	o.bb.WriteByte('}')
	return o.err
}

func writeJSONString(bb *bytes.Buffer, s string) {
	b, _ := json.Marshal(s) // marshalling a string cannot fail
	bb.Write(b)
}

// writeValue renders a decoded property value.
func writeValue(bb *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		bb.WriteString(`null`)
	case bool:
		bb.WriteString(strconv.FormatBool(t))
	case int64:
		bb.WriteString(strconv.FormatInt(t, 10))
	case uint64:
		bb.WriteString(strconv.FormatUint(t, 10))
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			writeJSONString(bb, strconv.FormatFloat(t, 'g', -1, 64))
		} else {
			bb.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
		}
	case string:
		writeJSONString(bb, t)
	case GUID:
		writeJSONString(bb, t.String())
	case time.Time:
		writeJSONString(bb, t.UTC().Format(time.RFC3339Nano))
	case []any:
		bb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				bb.WriteByte(',')
			}
			if err := writeValue(bb, x); err != nil {
				return err
			}
		}
		bb.WriteByte(']')
	case []Property:
		o := newObject(bb)
		for _, p := range t {
			o.value(p.Name, p.Value)
		}
		return o.close()
	case []byte:
		writeJSONString(bb, fmt.Sprintf("0x%X", t))
	default:
		return fmt.Errorf("unsupported property value type %T", v)
	}
	return nil
}

// MarshalJSON renders the event as a human readable JSON object with a stable
// field order.  Names are used in place of raw numeric codes wherever the
// provider schema supplies them; numeric codes are kept alongside.
func (e *Event) MarshalJSON() ([]byte, error) {
	var bb bytes.Buffer
	if err := e.writeJSON(&bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// AppendJSON appends the JSON rendering of the event to b.
func (e *Event) AppendJSON(b []byte) ([]byte, error) {
	bb := bytes.NewBuffer(b)
	err := e.writeJSON(bb)
	return bb.Bytes(), err
}

func (e *Event) writeJSON(bb *bytes.Buffer) error {
	o := newObject(bb)
	o.str(`Timestamp`, e.Timestamp.UTC().Format(time.RFC3339Nano))

	o.key(`Provider`)
	po := newObject(bb)
	po.strOmit(`Name`, e.ProviderName)
	po.str(`GUID`, e.ProviderGUID.String())
	po.close()

	o.uint(`EventID`, uint64(e.EventID))
	o.strOmit(`EventName`, e.EventName)
	o.uint(`Version`, uint64(e.Version))
	o.str(`Level`, nameOr(e.LevelName, LevelName(e.Level)))
	o.uint(`LevelValue`, uint64(e.Level))
	o.strOmit(`Task`, e.TaskName)
	o.uint(`TaskValue`, uint64(e.Task))
	o.strOmit(`Opcode`, e.OpcodeName)
	o.uint(`OpcodeValue`, uint64(e.Opcode))
	o.key(`Keywords`)
	kw := make([]any, 0, len(e.KeywordNames))
	for _, k := range e.KeywordNames {
		kw = append(kw, k)
	}
	writeValue(bb, kw)
	o.str(`KeywordsMask`, fmt.Sprintf("0x%x", e.Keywords))
	o.strOmit(`Channel`, e.ChannelName)
	o.uint(`ProcessID`, uint64(e.ProcessID))
	o.uint(`ThreadID`, uint64(e.ThreadID))
	o.uint(`ProcessorNumber`, uint64(e.ProcessorNumber))
	if !e.ActivityID.IsZero() {
		o.str(`ActivityID`, e.ActivityID.String())
	}
	if !e.RelatedActivityID.IsZero() {
		o.str(`RelatedActivityID`, e.RelatedActivityID.String())
	}
	o.str(`DecodingSource`, DecodingSourceName(e.DecodingSource))
	o.strOmit(`Message`, e.Message)
	o.value(`EventData`, e.Properties)
	if e.DecodingError != `` {
		o.str(`DecodingError`, e.DecodingError)
	}
	if len(e.RawUserData) > 0 {
		o.str(`RawUserData`, base64.StdEncoding.EncodeToString(e.RawUserData))
	}
	return o.close()
}

func nameOr(a, b string) string {
	if a != `` {
		return a
	}
	return b
}
