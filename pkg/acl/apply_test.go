//go:build windows

package acl

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aiyengar2/permissions/pkg/access"
	"github.com/aiyengar2/permissions/pkg/sid"
	"golang.org/x/sys/windows"
)

func TestMkdir_OwnersAndGroups(t *testing.T) {
	tests := []struct {
		Name string
		Dir  string
		// PreRunDir is a directory which
		// will exist being the test case runs
		PreRunDir    string
		AllowedSIDS  []windows.EXPLICIT_ACCESS
		ExpectedSddl string
		ErrExpected  bool
	}{
		{
			Name: "Create Directory With Local System and Administrators",
			Dir:  "LocalSystemAndAdmins",
			AllowedSIDS: []windows.EXPLICIT_ACCESS{
				access.GrantSid(windows.GENERIC_ALL, sid.LocalSystem()),
				access.GrantSid(windows.GENERIC_ALL, sid.BuiltinAdministrators()),
			},
			ExpectedSddl: "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
			// CreationExpected: true,
			ErrExpected: false,
		},
		{
			Name: "Create Directory With Local System and built-in users",
			Dir:  "LocalSystem",
			AllowedSIDS: []windows.EXPLICIT_ACCESS{
				access.GrantSid(windows.GENERIC_ALL, sid.LocalSystem()),
				access.GrantSid(windows.GENERIC_ALL, sid.Everyone()),
			},
			ExpectedSddl: "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)",
			// CreationExpected: true,
			ErrExpected: false,
		},
		{
			Name: "Create a directory without any explicit access",
			Dir:  "NoAccessRules",
			// CreationExpected: true,
			ErrExpected: false,
		},
		{
			Name:      "Do not create a directory which already exists",
			Dir:       "AlreadyExists",
			PreRunDir: "AlreadyExists",
			// CreationExpected: false,
			ErrExpected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			wd, err := os.Getwd()
			if err != nil {
				t.Fatalf("Failed to get working directory: %v", err)
			}

			dir := fmt.Sprintf("%s\\%s", wd, tc.Dir)

			if tc.PreRunDir != "" {
				err := os.Mkdir(fmt.Sprintf("%s\\%s", wd, tc.PreRunDir), 0777)
				if err != nil {
					t.Fatalf("Failed to create pre-run directory: %v", err)
				}
			}

			err = Mkdir(dir, tc.AllowedSIDS...)
			if err != nil && !tc.ErrExpected {
				t.Fatalf("Did not expecte error: %v", err)
			}

			// If we have not defined SIDS for the DACL then
			// it's expected to just use the default ACL
			if len(tc.AllowedSIDS) == 0 {
				return
			}

			description, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatalf("could not get named security info for directory %s: %v", dir, err)
			}

			if description.String() != tc.ExpectedSddl {
				t.Fatalf("expected sddl %s, got sddl %s", tc.ExpectedSddl, description.String())
			}
		})
	}
}

func TestApply(t *testing.T) {
	user, userDomain, _, err := sid.CurrentUser().LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	currentUser := filepath.Join(userDomain, user)
	group, groupDomain, _, err := sid.CurrentGroup().LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	currentGroup := filepath.Join(groupDomain, group)

	testCases := []struct {
		Name string

		Owner       *windows.SID
		Group       *windows.SID
		Permissions os.FileMode

		ExpectedACLPermissions []aclPermission
	}{
		{
			Name: "Set owner to current user",

			Owner: sid.CurrentUser(),
		},
		{
			Name: "Set group to current group",

			Group: sid.CurrentGroup(),
		},
		{
			Name: "Set 0777 permissions",

			// on an actual permissions change, the current owner and group reflect the permissions change
			Permissions: 0777,

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                "Everyone",
					Rights:            "Modify, Synchronize",
				},
				{
					AccessControlType: "Allow",
					ID:                currentUser,
					Rights:            "Modify, Synchronize",
				},
				{
					AccessControlType: "Allow",
					ID:                currentGroup,
					Rights:            "Modify, Synchronize",
				},
			},
		},
		{
			Name: "Set 0007 permissions",

			Permissions: 0007,

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                "Everyone",
					Rights:            "Modify, Synchronize",
				},
			},
		},
		{
			Name: "Set 0070 permissions",

			Permissions: 0070,

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                currentGroup,
					Rights:            "Modify, Synchronize",
				},
			},
		},
		{
			Name: "Set 0700 permissions",

			Permissions: 0700,

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                currentUser,
					Rights:            "Modify, Synchronize",
				},
			},
		},
	}

	// setup
	tempFile, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	f := tempFile.Name()
	defer os.Remove(f)

	// check if we need to skip powershell tests
	canRunPowershell, err := getACLExists()
	if err != nil {
		t.Fatal(err)
	}

	// set initial checks to ensure whether changes were made
	sd, err := windows.GetNamedSecurityInfo(
		f,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	lastOwner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	lastGroup, _, err := sd.Group()
	if err != nil {
		t.Fatal(err)
	}
	lastACLPermissions, err := getACLPermissions(f)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err = Apply(f, tc.Owner, tc.Group, tc.Permissions)
			if err != nil {
				t.Error(err)
				return
			}
			sd, err := windows.GetNamedSecurityInfo(
				f,
				windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
			)
			if err != nil {
				t.Error(err)
				return
			}

			t.Run("ValidateOwnerGroup", func(t *testing.T) {
				// validate owner
				if tc.Owner == nil {
					tc.Owner = lastOwner
				}
				lastOwner = tc.Owner
				owner, _, err := sd.Owner()
				if err != nil {
					t.Error(err)
					return
				}
				if owner.String() != tc.Owner.String() {
					t.Errorf("expected owner SID %s, found %s", tc.Owner, owner)
					return
				}

				// validate group
				if tc.Group == nil {
					tc.Group = lastGroup
				}
				lastGroup = tc.Group
				group, _, err := sd.Group()
				if err != nil {
					t.Error(err)
					return
				}
				if group.String() != tc.Group.String() {
					t.Errorf("expected group SID %s, found %s", tc.Group, group)
					return
				}
			})

			t.Run("ValidateAcl", func(t *testing.T) {
				// validate permissions
				if tc.ExpectedACLPermissions == nil {
					tc.ExpectedACLPermissions = lastACLPermissions
				}
				lastACLPermissions = tc.ExpectedACLPermissions
				if !canRunPowershell {
					t.Skip("Get-Acl is not available to execute tests on this machine")
				}
				aclPermissions, err := getACLPermissions(f)
				if err != nil {
					t.Errorf("encountered error while getting ACL: %s", err)
					return
				}
				if !reflect.DeepEqual(aclPermissions, tc.ExpectedACLPermissions) {
					t.Errorf("expected permissions %s, found %s", tc.ExpectedACLPermissions, aclPermissions)
				}
			})
		})
	}
}

type aclPermission struct {
	AccessControlType string
	ID                string
	Rights            string
}

func getACLExists() (bool, error) {
	output, err := runPowershell(`if (Get-Command Get-Acl -ErrorAction SilentlyContinue) { return $true } else { return $false }`)
	if err != nil {
		return false, err
	}
	exists := strings.Split(strings.TrimSpace(output), "\r\n")[0]
	return exists == "True", nil
}

// Note: until GetExplicitEntriesFromAcl is implemented in golang.org/x/sys/windows, which is the only recommended way to work with ACLs
// (as described in the Microsoft docs https://learn.microsoft.com/en-us/windows/win32/secauthz/getting-information-from-an-acl),
// this Go tests will have to use a workaround to directly call the `Get-Acl` powershell function to check permissions.
//
// TODO: refactor these tests once https://github.com/golang/sys/pull/84 (or a similar PR) is merged to add support for GetExplicitEntriesFromAcl
func getACLPermissions(filename string) ([]aclPermission, error) {
	output, err := runPowershell(
		fmt.Sprintf(strings.Join([]string{
			`$Path = "%s"`,
			`$acl = (Get-Acl $Path)`,
			`$acl.Access | ForEach-Object -Process {`,
			`$accessControlType = $_.AccessControlType`,
			`$id = $_.IdentityReference.Value`,
			`$rights = $_.FileSystemRights`,
			`"{0}|{1}|{2}" -f ($accessControlType), ($id), ($rights)`,
			`}`,
		}, "\r\n"), filename),
	)
	if err != nil {
		return nil, err
	}
	permissionLines := strings.Split(strings.TrimSpace(output), "\r\n")
	var permissions []aclPermission
	for _, line := range permissionLines {
		if len(line) == 0 {
			continue
		}
		lineSplit := strings.Split(line, "|")
		permissions = append(permissions, aclPermission{
			AccessControlType: lineSplit[0],
			ID:                lineSplit[1],
			Rights:            lineSplit[2],
		})
	}
	return permissions, nil
}

func runPowershell(script string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", script)
	cmd.Stderr = os.Stderr
	cmd.Stdout = &buf
	err := cmd.Run()
	return buf.String(), err
}
