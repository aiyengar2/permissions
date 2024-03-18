//go:build windows

package acl

import "testing"

func TestApply(t *testing.T) {
	testCases := []struct {
		Name string
	}{
		{
			Name: "Apply permissions to everyone for file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {

		})
	}
}
