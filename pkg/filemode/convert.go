//go:build windows

package filemode

import (
	"os"

	"github.com/aiyengar2/permissions/pkg/access"
	"github.com/aiyengar2/permissions/pkg/sid"
	"golang.org/x/sys/windows"
)

type AccessMasks struct {
	Owner    windows.ACCESS_MASK
	Group    windows.ACCESS_MASK
	Everyone windows.ACCESS_MASK
}

func Convert(fileMode os.FileMode) AccessMasks {
	mode := uint32(fileMode)

	return AccessMasks{
		Owner:    (windows.ACCESS_MASK)(((mode & 0700) << 23) | ((mode & 0200) << 9)),
		Group:    (windows.ACCESS_MASK)(((mode & 0070) << 26) | ((mode & 0020) << 12)),
		Everyone: (windows.ACCESS_MASK)(((mode & 0007) << 29) | ((mode & 0002) << 15)),
	}
}

func (m AccessMasks) ToExplicitAccess() []windows.EXPLICIT_ACCESS {
	return m.ToExplicitAccessCustom(nil, nil)
}

func (m AccessMasks) ToExplicitAccessCustom(owner, group *windows.SID) []windows.EXPLICIT_ACCESS {
	if owner == nil {
		owner = sid.CurrentUser()
	}
	if group == nil {
		group = sid.CurrentGroup()
	}

	return []windows.EXPLICIT_ACCESS{
		access.GrantSid(m.Owner, owner),
		access.GrantSid(m.Group, group),
		access.GrantSid(m.Everyone, sid.Everyone()),
	}
}
