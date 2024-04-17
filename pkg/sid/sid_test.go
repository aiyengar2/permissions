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
		LocalSystem,
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

func TestGetWellKnownSid(t *testing.T) {
	var test = []struct {
		name              string
		wellKnownSid      windows.WELL_KNOWN_SID_TYPE
		expectedSidString string
	}{
		{
			name:              "Test Windows Service Sid",
			wellKnownSid:      windows.WinServiceSid,
			expectedSidString: "S-1-5-6",
		},
		{
			name:              "Test Windows Local Service Sid",
			wellKnownSid:      windows.WinLocalServiceSid,
			expectedSidString: "S-1-5-19",
		},
		{
			name:              "Test Windows NT Authority Sid",
			wellKnownSid:      windows.WinNtAuthoritySid,
			expectedSidString: "S-1-5",
		},
	}
	for _, c := range test {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				assert.Nil(t, recover(), "encountered panic")
			}()
			assert.Equal(t, c.expectedSidString, GetWellKnownSid(c.wellKnownSid).String(), "SID string did not match expected value")
		})
	}

}
