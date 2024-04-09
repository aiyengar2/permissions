//go:build windows

package sid

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestSIDs(t *testing.T) {
	type sidFunc func() *windows.SID
	sidFuncs := []sidFunc{
		CurrentUser,
		CurrentGroup,
		BuiltinAdministrators,
		CreatorOwner,
		CreatorGroup,
		Everyone,
	}
	for _, f := range sidFuncs {
		funcName := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
		t.Run(funcName, func(t *testing.T) {
			defer func() {
				assert.Nil(t, recover(), "encountered panic")
			}()
			sid := f()
			assert.NotNil(t, sid, "found nil SID")
		})
	}
}
