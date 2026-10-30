package report

import (
	"reflect"

	"github.com/sigcomply/sigcomply-cli/internal/log"
)

// sanitizedSnapshot returns a deep copy of snap with log.Sanitize
// applied to every string field. Report cells carry text from vault
// files, resource names and API responses, and `report` output is often
// printed into a CI log, so no field may carry a newline, an escape
// sequence or a workflow command. Copying by reflection covers every
// field, including ones added later (TestReportFormats_SanitizeEveryField);
// the caller's snapshot is left as it was.
func sanitizedSnapshot(snap *Snapshot) *Snapshot {
	out, ok := sanitizedCopy(reflect.ValueOf(snap)).Interface().(*Snapshot)
	if !ok {
		return snap
	}
	return out
}

func sanitizedCopy(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.String:
		out := reflect.New(v.Type()).Elem()
		out.SetString(log.Sanitize(v.String()))
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(sanitizedCopy(v.Elem()))
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(sanitizedCopy(v.Index(i)))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(sanitizedCopy(iter.Key()), sanitizedCopy(iter.Value()))
		}
		return out
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			if !t.Field(i).IsExported() {
				// A struct with unexported state (time.Time) carries no
				// report text; copy it as a whole.
				return v
			}
		}
		out := reflect.New(t).Elem()
		for i := 0; i < t.NumField(); i++ {
			out.Field(i).Set(sanitizedCopy(v.Field(i)))
		}
		return out
	default:
		return v
	}
}
