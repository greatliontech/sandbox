package testdemand

import (
	"go/ast"
	"reflect"
	"strings"
	"testing"
)

// A host that delivers passes through; one that cannot skips, or
// fails where the variable demands the arm, naming the variable and
// the reason.
func TestLive(t *testing.T) {
	const variable = "TESTDEMAND_PROBE"
	for _, c := range []struct {
		name        string
		demanded    bool
		unavailable string
		ran         bool
		fatal, skip string
	}{
		{"delivered", false, "", true, "", ""},
		{"delivered, demanded", true, "", true, "", ""},
		{"unavailable", false, "no namespaces here", false, "", "no namespaces here"},
		{"unavailable, demanded", true, "no namespaces here", false, variable + " is set and no namespaces here", ""},
	} {
		if c.demanded {
			t.Setenv(variable, "1")
		} else {
			t.Setenv(variable, "")
		}
		r := Observe(func(t testing.TB) { Live(t, variable, c.unavailable) })
		if r.Ran != c.ran || r.FailureText != c.fatal || r.SkipText != c.skip {
			t.Errorf("%s: %+v", c.name, r)
		}
		if c.fatal != "" && !strings.Contains(r.FailureText, variable) {
			t.Errorf("%s: the failure does not name the variable: %q", c.name, r.FailureText)
		}
	}
}

// Degrade fails only where the surface is unavailable and demanded;
// every other case runs the arm.
func TestDegrade(t *testing.T) {
	const variable = "TESTDEMAND_PROBE"
	for _, c := range []struct {
		name        string
		demanded    bool
		unavailable string
		ran         bool
		fatal       string
	}{
		{"delivered", false, "", true, ""},
		{"delivered, demanded", true, "", true, ""},
		{"unavailable", false, "no placement here", true, ""},
		{"unavailable, demanded", true, "no placement here", false, variable + " is set and no placement here"},
	} {
		if c.demanded {
			t.Setenv(variable, "1")
		} else {
			t.Setenv(variable, "")
		}
		r := Observe(func(t testing.TB) { Degrade(t, variable, c.unavailable) })
		if r.Ran != c.ran || r.FailureText != c.fatal || r.SkipText != "" {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
}

// Every method of testing.TB is the Recorder's own, never the nil
// embed's: each is called with zero arguments under recover, and only
// the four that refuse by name may panic — a toolchain adding a
// method to the interface fails here, not in an observed arm.
func TestRecorderCoversTB(t *testing.T) {
	tb := reflect.TypeOf((*testing.TB)(nil)).Elem()
	refusing := map[string]bool{"TempDir": true, "Setenv": true, "Chdir": true, "ArtifactDir": true}
	for i := 0; i < tb.NumMethod(); i++ {
		m := tb.Method(i)
		if !ast.IsExported(m.Name) {
			continue // testing.TB's private marker method
		}
		var panicked any
		func() {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { panicked = recover() }()
				r := &Recorder{}
				method := reflect.ValueOf(r).MethodByName(m.Name)
				args := make([]reflect.Value, method.Type().NumIn())
				for j := range args {
					args[j] = reflect.Zero(method.Type().In(j))
				}
				if method.Type().IsVariadic() {
					args = args[:len(args)-1]
				}
				method.Call(args)
			}()
			<-done
		}()
		if panicked != nil {
			msg, _ := panicked.(string)
			if !refusing[m.Name] || !strings.HasPrefix(msg, "testdemand:") {
				t.Errorf("%s: %v", m.Name, panicked)
			}
		} else if refusing[m.Name] {
			t.Errorf("%s: did not refuse", m.Name)
		}
	}
}

// A message-free failure or skip is reported by the recorder's state,
// not by a message it did not receive.
func TestRecorderMessageFreeCalls(t *testing.T) {
	if r := Observe(func(t testing.TB) { t.FailNow() }); !r.Failed() || r.FailureText != "" || r.Ran {
		t.Errorf("FailNow: %+v", r)
	}
	if r := Observe(func(t testing.TB) { t.Fail() }); !r.Failed() || r.FailureText != "" || len(r.Errors) != 0 || !r.Ran {
		t.Errorf("Fail: %+v", r)
	}
	if r := Observe(func(t testing.TB) { t.SkipNow() }); !r.Skipped() || r.SkipText != "" || r.Failed() || r.Ran {
		t.Errorf("SkipNow: %+v", r)
	}
}
