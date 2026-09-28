package clientagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The same rule as on Unix, in Windows' terms: nothing another user on this
// machine can change may be run. A script or its directory must be owned by
// SYSTEM, Administrators, TrustedInstaller, an administrator or the agent's own
// account, and its access control list must give the right to change it to
// nobody else. An owner can always rewrite the list, which is why the owner is
// held to the same standard as the entries.
//
// C:\ProgramData lets every user create files in a new folder under it, so a
// scripts folder made there by hand fails this until its permissions are
// narrowed. `gowatcher-client service install` makes C:\ProgramData\Gryphon
// with permissions that pass.

// The rights that let a trustee change what runs: write or append the file (or
// add a file or folder to a directory), delete it or a child, rewrite its
// permissions or owner, or the generic rights that include those. Defined here
// rather than taken from x/sys, which does not name all of them.
const (
	rightWriteData   = 0x0002 // FILE_WRITE_DATA, FILE_ADD_FILE
	rightAppendData  = 0x0004 // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY
	rightDeleteChild = 0x0040 // FILE_DELETE_CHILD
	rightDelete      = 0x00010000
	rightWriteDAC    = 0x00040000
	rightWriteOwner  = 0x00080000
	rightGenericAll  = 0x10000000
	rightGenericWr   = 0x40000000

	changeRights = rightWriteData | rightAppendData | rightDeleteChild | rightDelete |
		rightWriteDAC | rightWriteOwner | rightGenericAll | rightGenericWr
)

// ACE types and flags, from winnt.h.
const (
	aceAccessAllowed         = 0x0
	aceAccessDenied          = 0x1
	aceAccessAllowedObject   = 0x5
	aceAccessDeniedObject    = 0x6
	aceAccessAllowedCallback = 0x9
	aceAccessDeniedCallback  = 0xA
	aceInheritOnly           = 0x8
)

// Well-known SIDs a script may belong to or be writable by.
const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	// OWNER RIGHTS stands for whoever owns the object, who is checked
	// separately; CREATOR OWNER in an entry that is not inherit-only
	// grants nothing.
	sidOwnerRights  = "S-1-3-4"
	sidCreatorOwner = "S-1-3-0"
)

func unsafePermissions(path string, _ os.FileInfo) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Sprintf("has permissions the agent cannot read (%v)", err)
	}

	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "has no owner the agent can read"
	}
	if !trustedSID(owner) {
		return fmt.Sprintf("is owned by %s, not Administrators, SYSTEM or the agent's account (fix: icacls %q /setowner *S-1-5-32-544)",
			accountName(owner), path)
	}

	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		return "has no access control list, so every user on this machine can change it"
	}
	if err != nil {
		return fmt.Sprintf("has permissions the agent cannot read (%v)", err)
	}
	for _, e := range aceEntries(dacl) {
		if e.flags&aceInheritOnly != 0 {
			continue
		}
		switch e.kind {
		case aceAccessDenied, aceAccessDeniedObject, aceAccessDeniedCallback:
			// A denial only ever narrows what the grants allow. Judging the
			// grants alone is stricter, never looser.
			continue
		case aceAccessAllowed, aceAccessAllowedCallback:
			if e.mask&changeRights != 0 && !trustedSID(e.sid) {
				return fmt.Sprintf("can be changed by %s (fix: icacls %q /remove:g *%s)",
					accountName(e.sid), path, e.sid.String())
			}
		default:
			if e.mask&changeRights != 0 {
				return "has a permission entry the agent cannot judge"
			}
		}
	}
	return ""
}

// ace is the part of an access control entry the rule needs.
type ace struct {
	kind  byte
	flags byte
	mask  uint32
	sid   *windows.SID // nil for an entry type without a SID at the usual place
}

// aceEntries walks an ACL in place. The layout is winnt.h's: an 8-byte ACL
// header whose fourth field is the entry count, then the entries back to back,
// each starting with a type byte, a flags byte and its own size, followed by
// the access mask and, for the plain and callback types, the SID.
func aceEntries(acl *windows.ACL) []ace {
	base := unsafe.Pointer(acl)
	size := int(*(*uint16)(unsafe.Add(base, 2)))
	count := int(*(*uint16)(unsafe.Add(base, 4)))
	var out []ace
	off := 8
	for i := 0; i < count && off+8 <= size; i++ {
		p := unsafe.Add(base, off)
		kind := *(*byte)(p)
		flags := *(*byte)(unsafe.Add(p, 1))
		aceSize := int(*(*uint16)(unsafe.Add(p, 2)))
		if aceSize < 8 || off+aceSize > size {
			// A malformed list: judge it as one that grants something to
			// someone unknown.
			out = append(out, ace{kind: 0xFF, mask: changeRights})
			break
		}
		e := ace{kind: kind, flags: flags, mask: *(*uint32)(unsafe.Add(p, 4))}
		switch kind {
		case aceAccessAllowed, aceAccessDenied, aceAccessAllowedCallback, aceAccessDeniedCallback:
			e.sid = (*windows.SID)(unsafe.Add(p, 8))
		}
		out = append(out, e)
		off += aceSize
	}
	return out
}

// trustedSID reports whether sid may own or change a script: one of the
// system's own accounts, the agent's account, or an administrator.
func trustedSID(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	switch sid.String() {
	case sidSystem, sidAdministrators, sidTrustedInstaller, sidOwnerRights, sidCreatorOwner:
		return true
	}
	if self := agentSID(); self != nil && sid.Equals(self) {
		return true
	}
	return isAdministrator(sid)
}

var (
	agentSIDOnce  sync.Once
	agentSIDValue *windows.SID
)

// agentSID is the account the agent runs as: NT SERVICE\GryphonAgent under
// the service, the signed-in user otherwise.
func agentSID() *windows.SID {
	agentSIDOnce.Do(func() {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return
		}
		if copied, err := user.User.Sid.Copy(); err == nil {
			agentSIDValue = copied
		}
	})
	return agentSIDValue
}

var (
	netapi32                   = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserGetLocalGroups  = netapi32.NewProc("NetUserGetLocalGroups")
	errNotAdministratorLookup  = errors.New("not a user account")
	administratorsGroupOnce    sync.Once
	administratorsGroupName    string
	administratorsGroupLookErr error
)

// isAdministrator reports whether a user account is in the local
// Administrators group, directly or through a domain group. The group is
// matched by its SID's name, since the name itself is translated on
// non-English Windows. Anything that cannot be looked up is not an
// administrator.
func isAdministrator(sid *windows.SID) bool {
	administratorsGroupOnce.Do(func() {
		admins, err := windows.StringToSid(sidAdministrators)
		if err != nil {
			administratorsGroupLookErr = err
			return
		}
		administratorsGroupName, _, _, administratorsGroupLookErr = admins.LookupAccount("")
	})
	if administratorsGroupLookErr != nil || administratorsGroupName == "" {
		return false
	}
	groups, err := localGroupsOf(sid)
	if err != nil {
		return false
	}
	for _, g := range groups {
		if strings.EqualFold(g, administratorsGroupName) {
			return true
		}
	}
	return false
}

// localGroupsOf lists the local groups a user account is in, including
// through the global groups it belongs to (LG_INCLUDE_INDIRECT).
func localGroupsOf(sid *windows.SID) ([]string, error) {
	account, domain, kind, err := sid.LookupAccount("")
	if err != nil {
		return nil, err
	}
	if kind != windows.SidTypeUser {
		return nil, errNotAdministratorLookup
	}
	name := account
	if domain != "" {
		name = domain + `\` + account
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	const (
		levelNamesOnly    = 0
		lgIncludeIndirect = 1
		maxPreferredLen   = 0xFFFFFFFF
	)
	var buf *byte
	var read, total uint32
	r, _, _ := procNetUserGetLocalGroups.Call(0, uintptr(unsafe.Pointer(namePtr)),
		levelNamesOnly, lgIncludeIndirect, uintptr(unsafe.Pointer(&buf)), maxPreferredLen,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	if buf != nil {
		defer windows.NetApiBufferFree(buf)
	}
	if r != 0 {
		return nil, windows.Errno(r)
	}
	// LOCALGROUP_USERS_INFO_0 is one pointer to the group's name.
	entries := unsafe.Slice((**uint16)(unsafe.Pointer(buf)), read)
	out := make([]string, 0, read)
	for _, e := range entries {
		out = append(out, windows.UTF16PtrToString(e))
	}
	return out, nil
}

// accountName is DOMAIN\name for a SID, or the SID itself when it has no name.
func accountName(sid *windows.SID) string {
	if sid == nil {
		return "an unknown account"
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// scriptExtensions are what Windows can run from a name alone, and PowerShell,
// which the agent starts itself.
var scriptExtensions = map[string]bool{".exe": true, ".com": true, ".bat": true, ".cmd": true, ".ps1": true}

func executable(path string, _ os.FileInfo) bool {
	return scriptExtensions[strings.ToLower(filepath.Ext(path))]
}

const notExecutableHint = "Windows runs .exe, .com, .bat, .cmd and .ps1 files; name it with one of those"

// scriptCommand runs a .ps1 through Windows PowerShell, named by its full
// path so a powershell.exe elsewhere on PATH is never the one run. The
// execution policy is bypassed for this one file: it is a guard against
// running scripts by accident, and this one was put here on purpose by an
// administrator. Everything else Windows starts directly.
func scriptCommand(ctx context.Context, path string) *exec.Cmd {
	if strings.EqualFold(filepath.Ext(path), ".ps1") {
		ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
		return exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-File", path)
	}
	return exec.CommandContext(ctx, path)
}

// runScript runs the script in a job object and ends the whole job when the
// check's time is up, so that what a batch file or PowerShell started does
// not outlive it -- the process group of the Unix side. The script is added to
// the job just after it starts, so a child it starts in that first instant
// escapes; that is the one gap. Without a job the script alone is stopped.
func runScript(cmd *exec.Cmd) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return cmd.Run()
	}
	defer windows.CloseHandle(job)

	var mu sync.Mutex
	inJob := false
	cmd.Cancel = func() error {
		mu.Lock()
		defer mu.Unlock()
		if inJob {
			return windows.TerminateJobObject(job, 1)
		}
		return cmd.Process.Kill()
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil {
		if windows.AssignProcessToJobObject(job, h) == nil {
			mu.Lock()
			inJob = true
			mu.Unlock()
		}
		windows.CloseHandle(h)
	}
	return cmd.Wait()
}
