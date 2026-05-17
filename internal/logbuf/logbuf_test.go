package logbuf

import (
	"log"
	"reflect"
	"testing"
)

func TestWrite_SplitsOnNewline(t *testing.T) {
	b := New(10)
	b.Write([]byte("alpha\nbeta\n"))
	if got, want := b.Tail(0), []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}

func TestWrite_HandlesPartialLines(t *testing.T) {
	b := New(10)
	b.Write([]byte("alp"))
	b.Write([]byte("ha\nbe"))
	b.Write([]byte("ta\n"))
	if got, want := b.Tail(0), []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}

func TestRingEviction(t *testing.T) {
	b := New(3)
	for _, s := range []string{"one\n", "two\n", "three\n", "four\n"} {
		b.Write([]byte(s))
	}
	if got, want := b.Tail(0), []string{"two", "three", "four"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}

func TestTail_LimitsToN(t *testing.T) {
	b := New(10)
	for _, s := range []string{"a\n", "b\n", "c\n", "d\n"} {
		b.Write([]byte(s))
	}
	if got, want := b.Tail(2), []string{"c", "d"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}

func TestAsLogWriter(t *testing.T) {
	b := New(10)
	lg := log.New(b, "", 0)
	lg.Println("hello")
	lg.Println("world")
	if got, want := b.Tail(0), []string{"hello", "world"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}
