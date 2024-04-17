//go:build windows

package access

import (
	"golang.org/x/sys/windows"
)

// DenySid creates an EXPLICIT_ACCESS instance denying permissions to the provided SID.
func DenySid(accessPermissions windows.ACCESS_MASK, sid *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: accessPermissions,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// DenyName creates an EXPLICIT_ACCESS instance denying permissions to the provided name.
func DenyName(accessPermissions windows.ACCESS_MASK, name string) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: accessPermissions,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_NAME,
			TrusteeValue: windows.TrusteeValueFromString(name),
		},
	}
}
