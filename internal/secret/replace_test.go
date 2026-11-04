package secret

import (
	"errors"
	"testing"
)

func TestSetItem(t *testing.T) {
	dup, owner, denied := errors.New("duplicate"), errors.New("owner"), errors.New("denied")
	isDup := func(e error) bool { return e == dup }
	replaceable := func(e error) bool { return e == owner }
	for _, v := range []struct {
		name                 string
		add, update, remove  []error // results per call
		wantRemoved, wantErr bool
		wantCalls            string
	}{
		{name: "new item", add: []error{nil}, wantCalls: "a"},
		{name: "update", add: []error{dup}, update: []error{nil}, wantCalls: "au"},
		{name: "update denied keeps item", add: []error{dup}, update: []error{denied}, wantErr: true, wantCalls: "au"},
		{name: "replace", add: []error{dup, nil}, update: []error{owner}, remove: []error{nil}, wantCalls: "aura"},
		{name: "delete fails keeps item", add: []error{dup}, update: []error{owner}, remove: []error{denied}, wantErr: true, wantCalls: "aur"},
		{name: "re-add fails after delete", add: []error{dup, denied}, update: []error{owner}, remove: []error{nil}, wantErr: true, wantRemoved: true, wantCalls: "aura"},
		{name: "add fails", add: []error{denied}, wantErr: true, wantCalls: "a"},
	} {
		t.Run(v.name, func(t *testing.T) {
			calls := ""
			next := func(c string, r *[]error) func() error {
				return func() error { calls += c; e := (*r)[0]; *r = (*r)[1:]; return e }
			}
			err := setItem(next("a", &v.add), next("u", &v.update), next("r", &v.remove), isDup, replaceable)
			var re *ReplaceError
			if (err != nil) != v.wantErr || errors.As(err, &re) != v.wantRemoved || calls != v.wantCalls {
				t.Fatalf("err=%v removed=%v calls=%q", err, errors.As(err, &re), calls)
			}
			if v.wantRemoved && !errors.Is(err, denied) {
				t.Fatal("ReplaceError must wrap the add error")
			}
		})
	}
}
