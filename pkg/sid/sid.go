//go:build windows

package sid

import (
	"os/user"
	"syscall"

	"golang.org/x/sys/windows"
)

func CurrentUser() *windows.SID {
	return mustStrToSid(mustGetUser().Uid)
}

func CurrentGroup() *windows.SID {
	return mustStrToSid(mustGetUser().Gid)
}

func BuiltinAdministrators() *windows.SID {
	return mustGetSid(windows.WinBuiltinAdministratorsSid)
}

func CreatorOwner() *windows.SID {
	return mustGetSid(windows.WinCreatorOwnerSid)
}

func CreatorGroup() *windows.SID {
	return mustGetSid(windows.WinCreatorGroupSid)
}

func Everyone() *windows.SID {
	return mustGetSid(windows.WinWorldSid)
}

func mustGetUser() *user.User {
	currentUser, err := user.Current()
	if err != nil {
		panic(err)
	}
	return currentUser
}

func mustStrToSid(sidStr string) *windows.SID {
	var sid *windows.SID
	sidPtr, err := syscall.UTF16PtrFromString(sidStr)
	if err != nil {
		panic(err)
	}
	err = windows.ConvertStringSidToSid(sidPtr, &sid)
	if err != nil {
		panic(err)
	}
	return sid
}

func mustGetSid(sidType windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	sid, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		panic(err)
	}
	return sid
}
