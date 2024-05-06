//go:build windows

package acl

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type securityArgs struct {
	path string

	owner *windows.SID
	group *windows.SID

	access []windows.EXPLICIT_ACCESS
}

func (a *securityArgs) ToSecurityAttributes() (*windows.SecurityAttributes, error) {
	// define empty security descriptor
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}

	// define security attributes using descriptor
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.SecurityDescriptor = sd

	if len(a.access) == 0 {
		// security attribute should simply inherit parent rules
		sa.InheritHandle = 1
		return &sa, nil
	}

	// apply provided access rules to the DACL
	dacl, err := a.ToDACL()
	if err != nil {
		return nil, err
	}
	err = sd.SetDACL(dacl, true, false)
	if err != nil {
		return nil, err
	}

	// set the protected DACL flag to prevent the DACL of the security descriptor from being modified by inheritable ACEs
	// (i.e. prevent parent folders from modifying this ACL)
	err = sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED)
	if err != nil {
		return nil, err
	}

	return &sa, nil
}

func (a *securityArgs) ToSecurityInfo() windows.SECURITY_INFORMATION {
	var securityInfo windows.SECURITY_INFORMATION

	if a.owner != nil {
		// override owner
		securityInfo |= windows.OWNER_SECURITY_INFORMATION
	}

	if a.group != nil {
		// override group
		securityInfo |= windows.GROUP_SECURITY_INFORMATION
	}

	if len(a.access) != 0 {
		// override DACL
		securityInfo |= windows.DACL_SECURITY_INFORMATION
		securityInfo |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	}

	return securityInfo
}

func (a *securityArgs) ToDACL() (*windows.ACL, error) {
	if len(a.access) == 0 {
		// No rules were specified
		return nil, nil
	}
	return windows.ACLFromEntries(a.access, nil)
}
