//go:build windows

package acl

import (
	"fmt"
	"os"
	"unsafe"

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

// Mkdir creates a directory using the given explicitAccess rules for a number of SIDs. If no windows.EXPLICIT_ACCESS
// rules are provided then the directory will inherit its ACL from the parent directory. If the specified
// directory already exists or another error is encountered, Mkdir will return false and the relevant error.
// Upon Successful creation of the directory, Mkdir will return 'true' and a nil error.
func Mkdir(name string, explicitAccess ...windows.EXPLICIT_ACCESS) (bool, error) {
	if name == "" {
		return false, fmt.Errorf("must supply a directory name")
	}

	// check if the file already exists
	_, err := os.Stat(name)
	if err == nil {
		return false, nil
	}

	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return false, fmt.Errorf("failed to create security descriptor: %v", err)
	}

	// if we haven't been provided DACL rules
	// we should defer to the parent directory
	inheritACL := explicitAccess == nil
	if explicitAccess != nil && len(explicitAccess) != 0 {
		acl, err := windows.ACLFromEntries(explicitAccess, nil)
		if err != nil {
			return false, fmt.Errorf("failed to create ACL from explicit access entries: %v", err)
		}

		err = sd.SetDACL(acl, true, inheritACL)
		if err != nil {
			return false, fmt.Errorf("failed to configure DACL for security desctriptor: %v", err)
		}
	}

	// set the protected DACL flag to prevent the DACL of the security descriptor from being modified by inheritable ACEs
	// (i.e. prevent parent folders from modifying this ACL)
	if !inheritACL {
		err = sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED)
		if err != nil {
			return false, fmt.Errorf("failed to configure protected DACL for security descriptor: %v", err)
		}
	}

	var securityAttribute windows.SecurityAttributes
	securityAttribute.Length = uint32(unsafe.Sizeof(securityAttribute))
	inheritHandle := 1
	if !inheritACL {
		inheritHandle = 0
	}
	securityAttribute.InheritHandle = uint32(inheritHandle)
	securityAttribute.SecurityDescriptor = sd

	namePntr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}

	if err = windows.CreateDirectory(namePntr, &securityAttribute); err != nil {
		return false, fmt.Errorf("failed to create directory with custom ACE: %v", err)
	}

	return true, nil
}

// Apply performs both Chmod and Chown at the same time, where the filemode's owner and group will correspond to
// the provided owner and group (or the current owner and group, if they are set to nil)
func Apply(name string, owner *windows.SID, group *windows.SID, fileMode os.FileMode) error {
	// copied from https://github.com/hectane/go-acl/blob/master/chmod.go
	return ApplyCustom(name, owner, group, filemode.Convert(fileMode).ToExplicitAccessCustom(owner, group, nil)...)
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
