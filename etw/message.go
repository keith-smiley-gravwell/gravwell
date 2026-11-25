/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

import (
	"fmt"
	"strconv"
	"strings"
)

// FormatMessage substitutes FormatMessage style inserts (%1, %2!s!, ...) in
// an event message template with the given arguments.  %% becomes %, %n a
// newline, %t a tab, %r a carriage return and %0 terminates the message.
// Unknown inserts are left in place.
func FormatMessage(tmpl string, args []string) string {
	if !strings.Contains(tmpl, `%`) {
		return strings.TrimSpace(tmpl)
	}
	var sb strings.Builder
	for i := 0; i < len(tmpl); i++ {
		c := tmpl[i]
		if c != '%' || i+1 >= len(tmpl) {
			sb.WriteByte(c)
			continue
		}
		n := tmpl[i+1]
		switch {
		case n == '%':
			sb.WriteByte('%')
			i++
		case n == 'n':
			sb.WriteByte('\n')
			i++
		case n == 't':
			sb.WriteByte('\t')
			i++
		case n == 'r':
			sb.WriteByte('\r')
			i++
		case n == '0':
			return strings.TrimSpace(sb.String())
		case n >= '1' && n <= '9':
			j := i + 1
			for j < len(tmpl) && j-i <= 2 && tmpl[j] >= '0' && tmpl[j] <= '9' {
				j++
			}
			idx, _ := strconv.Atoi(tmpl[i+1 : j])
			// optional !printf format!
			end := j
			if j < len(tmpl) && tmpl[j] == '!' {
				if k := strings.IndexByte(tmpl[j+1:], '!'); k >= 0 {
					end = j + 1 + k + 1
				}
			}
			if idx >= 1 && idx <= len(args) {
				sb.WriteString(args[idx-1])
			} else {
				sb.WriteString(tmpl[i:end])
			}
			i = end - 1
		default:
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

// valueString renders a decoded property value for message substitution.
func valueString(v any) string {
	switch t := v.(type) {
	case nil:
		return ``
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, valueString(x))
		}
		return strings.Join(parts, `, `)
	case []Property:
		parts := make([]string, 0, len(t))
		for _, p := range t {
			parts = append(parts, p.Name+`=`+valueString(p.Value))
		}
		return strings.Join(parts, `, `)
	default:
		return fmt.Sprint(t)
	}
}

// MessageArgs returns the top level property values as message inserts.
func (e *Event) MessageArgs() []string {
	args := make([]string, 0, len(e.Properties))
	for _, p := range e.Properties {
		args = append(args, valueString(p.Value))
	}
	return args
}
