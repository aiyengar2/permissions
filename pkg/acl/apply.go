//go:build windows

package acl

import (
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
	return ApplyCustom(name, owner, group, filemode.Convert(fileMode).ToExplicitAccessCustom(owner, group)...)
}

// ApplyCustom performs a Chmod (if owner and group are provided) and sets a custom ACL based on the provided EXPLICIT_ACCESS rules
// To create EXPLICIT_ACCESS rules, see the helper functions in pkg/access
func ApplyCustom(name string, owner *windows.SID, group *windows.SID, explicitAccess ...windows.EXPLICIT_ACCESS) error {
	var securityInfo windows.SECURITY_INFORMATION
	// set owner
	if owner != nil {
		// override owner
		securityInfo |= windows.OWNER_SECURITY_INFORMATION
	}

	// set group
	if group != nil {
		// override group
		securityInfo |= windows.GROUP_SECURITY_INFORMATION
	}

	// set ACL
	var dacl *windows.ACL
	if len(explicitAccess) != 0 {
		var err error
		dacl, err = windows.ACLFromEntries(explicitAccess, nil)
		if err != nil {
			return err
		}
		securityInfo |= windows.DACL_SECURITY_INFORMATION
		securityInfo |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	}

	// check if something needs to be modified
	if securityInfo == 0 {
		return nil
	}

	return windows.SetNamedSecurityInfo(
		name,
		windows.SE_FILE_OBJECT,
		securityInfo,
		owner,
		group,
		dacl,
		nil,
	)
}
