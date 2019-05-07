package sysvisor

import "testing"

func TestIsKernelSupported(t *testing.T) {

	var tests = []struct {
		input string
		want bool
	}{
		{"4.10", true},
		{"4.9", false},
		{"4.11", true},
		{"3.0", false},
		{"5.1", true},
		{"4.18.0-17", true},
		{"4.10.5", true},
		{"4.9.20", false},
	}

	for _, test := range tests {
		got, err := IsKernelSupported(test.input)
		if err != nil {
			t.Errorf("IsKernelSupported(%q) returned error %v", test.input, err)
		}
		if got != test.want {
			t.Errorf("IsKernelSupported(%q) = %v", test.input, got)
		}
	}
}
