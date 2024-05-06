//go:build windows

package acl

import (
	"fmt"
	"os"

	"github.com/aiyengar2/permissions/pkg/filemode"
	"golang.org/x/sys/windows"
)

// Chown changes the owner and group of the file / directory and applies a default ACL that provides
// Owner: read, write, execute
// Group: read, execute
// Everyone: read, execute
//
// To set custom permissions, use Apply or ApplyCustom instead directly
func Chown(name string, owner *windows.SID, group *windows.SID) error {
	return Apply(name, owner, group, 0755)
}

// Chmod changes the file's ACL to match the provided unix permissions. It uses the file's current owner and group
// to set the ACL permissions.
func Chmod(name string, fileMode os.FileMode) error {
	return Apply(name, nil, nil, fileMode)
}

// Apply performs both Chmod and Chown at the same time, where the filemode's owner and group will correspond to
// the provided owner and group (or the current owner and group, if they are set to nil)
func Apply(name string, owner *windows.SID, group *windows.SID, fileMode os.FileMode) error {
	// copied from https://github.com/hectane/go-acl/blob/master/chmod.go
	isDir := false
	return apply(name, isDir, owner, group, filemode.Convert(fileMode).ToExplicitAccessCustom(owner, group)...)
}

// Mkdir creates a directory with the provided permissions if it does not exist already
// If it already exists, it just applies the provided permissions
func Mkdir(name string, explicitAccess ...windows.EXPLICIT_ACCESS) error {
	isDir := true
	return apply(name, isDir, nil, nil, explicitAccess...)
}

// apply performs a Chmod (if owner and group are provided) and sets a custom ACL based on the provided EXPLICIT_ACCESS rules
// To create EXPLICIT_ACCESS rules, see the helper functions in pkg/access
func apply(path string, directory bool, owner *windows.SID, group *windows.SID, access ...windows.EXPLICIT_ACCESS) error {
	if path == "" {
		return fmt.Errorf("cannot apply permissions on empty path")
	}

	args := securityArgs{
		path:   path,
		owner:  owner,
		group:  group,
		access: access,
	}

	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	exists := os.IsNotExist(err)

	if directory && !exists {
		pathPtr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		sa, err := args.ToSecurityAttributes()
		if err != nil {
			return err
		}
		if err = windows.CreateDirectory(pathPtr, sa); err != nil {
			return err
		}
		return nil
	}

	securityInfo := args.ToSecurityInfo()
	if securityInfo == 0 {
		// nothing to change
		return nil
	}

	dacl, err := args.ToDACL()
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		securityInfo,
		owner,
		group,
		dacl,
		nil,
	)
}
