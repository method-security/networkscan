package ndr

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// knownTagValues is the set of valueless `ndr:"..."` entries the library acts
// on. A tag outside this set is almost always a typo, and because unrecognised
// tags were previously ignored the mistake surfaced as a silently wrong wire
// format rather than as an error.
var knownTagValues = map[string]bool{
	TagConformant:   true,
	TagVarying:      true,
	TagPointer:      true,
	TagTopLevel:     true,
	TagFullPointer:  true,
	TagPipe:         true,
	TagSkipNull:     true,
	TagNotNullPtr:   true,
	TagUnionTag:     true,
	TagUnionField:   true,
	TagEncapsulated: true,
	// Injected by the library while encoding/decoding arrays of strings; only
	// ever seen on synthesised tags, but accepted here for completeness.
	subStringArrayValue: true,
}

// knownTagKeys is the set of `key:value` entries the library acts on.
var knownTagKeys = map[string]bool{
	TagMaxCount: true,
	// Injected by addSizeToTag for RawBytes fields.
	"size": true,
}

func knownNames(m map[string]bool) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// validateStructTags walks a type and reports the first unrecognised ndr tag it
// finds. Types are visited once, which also bounds recursion on self-referential
// types.
func validateStructTags(t reflect.Type, path string, seen map[reflect.Type]bool, depth int) error {
	if depth > maxTypeWalkDepth {
		return nil
	}
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return validateStructTags(t.Elem(), path+"[]", seen, depth+1)
	case reflect.Struct:
	default:
		return nil
	}
	if seen[t] {
		return nil
	}
	seen[t] = true

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported: never consulted
		}
		fieldPath := path + "." + f.Name
		raw, ok := f.Tag.Lookup(ndrNameSpace)
		if ok {
			ndrTag := parseTags(f.Tag)
			for _, v := range ndrTag.Values {
				if v == "" {
					continue
				}
				if !knownTagValues[v] {
					return Errorf("unknown ndr tag %q on field %s (in `ndr:%q`); valid tags are: %s",
						v, fieldPath, raw, knownNames(knownTagValues))
				}
			}
			for k, val := range ndrTag.Map {
				if !knownTagKeys[k] {
					return Errorf("unknown ndr tag key %q on field %s (in `ndr:%q`); valid keys are: %s",
						k, fieldPath, raw, knownNames(knownTagKeys))
				}
				if k == TagMaxCount {
					if err := validateMaxCount(t, fieldPath, val); err != nil {
						return err
					}
				}
			}
		}
		if err := validateStructTags(f.Type, fieldPath, seen, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// validateMaxCount checks that a maxcount tag is either a non-negative literal
// or the name of a sibling field, catching a misspelled sibling at the point the
// struct is first used rather than mid-encode.
func validateMaxCount(parent reflect.Type, fieldPath, val string) error {
	if val == "" {
		return Errorf("empty maxcount tag on field %s", fieldPath)
	}
	if n, err := strconv.Atoi(val); err == nil {
		if n < 0 {
			return Errorf("negative maxcount %d on field %s", n, fieldPath)
		}
		return nil
	}
	if _, ok := parent.FieldByName(val); !ok {
		return Errorf("maxcount on field %s refers to sibling field %q, which does not exist in %s",
			fieldPath, val, parent.Name())
	}
	return nil
}

// checkTags validates the ndr tags on the type of s.
func checkTags(s interface{}) error {
	var t reflect.Type
	if rv, ok := s.(reflect.Value); ok {
		if !rv.IsValid() {
			return nil
		}
		t = rv.Type()
	} else {
		if s == nil {
			return nil
		}
		t = reflect.TypeOf(s)
	}
	name := t.Name()
	if name == "" {
		name = t.String()
	}
	return validateStructTags(t, name, map[reflect.Type]bool{}, 0)
}
