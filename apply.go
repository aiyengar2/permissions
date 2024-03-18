//go:build windows

package acl

import (
	"golang.org/x/sys/windows"
)

// Apply sets the ACL on the file with the provided information. Any existing configuration is removed.
func Apply(name string, owner *windows.SID, group *windows.SID, explicitEntries ...windows.EXPLICIT_ACCESS) error {
	return apply(name, owner, group, explicitEntries...)
}

func apply(name string, owner *windows.SID, group *windows.SID, explicitEntries ...windows.EXPLICIT_ACCESS) error {
	dacl, err := windows.ACLFromEntries(explicitEntries, nil)
	if err != nil {
		return err
	}
	var securityInfo windows.SECURITY_INFORMATION
	if explicitEntries != nil {
		securityInfo = windows.DACL_SECURITY_INFORMATION
	}
	if owner != nil {
		// override owner
		securityInfo = securityInfo & windows.OWNER_SECURITY_INFORMATION
	}
	if group != nil {
		// override group
		securityInfo = securityInfo & windows.GROUP_SECURITY_INFORMATION
	}
	if securityInfo == 0 {
		// nothing to update
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
