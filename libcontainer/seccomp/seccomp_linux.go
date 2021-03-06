// +build linux,cgo,seccomp

package seccomp

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	libseccomp "github.com/nestybox/sysbox-libs/libseccomp-golang"
	"github.com/opencontainers/runc/libcontainer/configs"

	"golang.org/x/sys/unix"
)

var (
	actAllow  = libseccomp.ActAllow
	actTrap   = libseccomp.ActTrap
	actKill   = libseccomp.ActKill
	actTrace  = libseccomp.ActTrace.SetReturnCode(int16(unix.EPERM))
	actLog    = libseccomp.ActLog
	actErrno  = libseccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
	actNotify = libseccomp.ActNotify
)

const (
	// Linux system calls can have at most 6 arguments
	syscallMaxArguments int = 6
)

// Loads a seccomp filter with the given seccomp config. If the given config contains a
// seccomp notify action, returns a file descriptor that can be used by a tracer process
// to retrieve such notifications from the kernel.
func LoadSeccomp(config *configs.Seccomp) (int32, error) {
	var notifyFd libseccomp.ScmpFd

	if config == nil {
		return -1, errors.New("cannot initialize Seccomp - nil config passed")
	}

	defaultAction, err := getAction(config.DefaultAction, nil)
	if err != nil {
		return -1, errors.New("error initializing seccomp - invalid default action")
	}

	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return -1, fmt.Errorf("error creating filter: %s", err)
	}

	// Add extra architectures
	for _, arch := range config.Architectures {
		scmpArch, err := libseccomp.GetArchFromString(arch)
		if err != nil {
			return -1, fmt.Errorf("error validating Seccomp architecture: %s", err)
		}

		if err := filter.AddArch(scmpArch); err != nil {
			return -1, fmt.Errorf("error adding architecture to seccomp filter: %s", err)
		}
	}

	// Unset no new privs bit (i.e., libseccomp won't touch it when loading the filter)
	if err := filter.SetNoNewPrivsBit(false); err != nil {
		return -1, fmt.Errorf("error setting no new privileges: %s", err)
	}

	// Add a rule for each syscall
	notify := false
	for _, call := range config.Syscalls {
		if call == nil {
			return -1, errors.New("encountered nil syscall while initializing Seccomp")
		}

		if call.Action == configs.Notify && notify == false {
			if err := prepNotify(filter); err != nil {
				return -1, fmt.Errorf("error preparing seccomp notifications: %s", err)
			}
			notify = true
		}

		if err = matchCall(filter, call); err != nil {
			return -1, err
		}
	}

	if err = filter.Load(); err != nil {
		return -1, fmt.Errorf("error loading seccomp filter into kernel: %s", err)
	}

	// If the filter contains a notify action, get the notification file-descriptor
	if notify {
		fd, err := filter.GetNotifFd()
		if err != nil {
			return -1, fmt.Errorf("error getting filter notification fd: %s", err)
		}
		notifyFd = fd
	}

	return int32(notifyFd), nil
}

// IsEnabled returns if the kernel has been configured to support seccomp.
func IsEnabled() bool {
	// Try to read from /proc/self/status for kernels > 3.8
	s, err := parseStatusFile("/proc/self/status")
	if err != nil {
		// Check if Seccomp is supported, via CONFIG_SECCOMP.
		if err := unix.Prctl(unix.PR_GET_SECCOMP, 0, 0, 0, 0); err != unix.EINVAL {
			// Make sure the kernel has CONFIG_SECCOMP_FILTER.
			if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, 0, 0, 0); err != unix.EINVAL {
				return true
			}
		}
		return false
	}
	_, ok := s["Seccomp"]
	return ok
}

// Convert Libcontainer Action to Libseccomp ScmpAction
func getAction(act configs.Action, errnoRet *uint) (libseccomp.ScmpAction, error) {
	switch act {
	case configs.Kill:
		return actKill, nil
	case configs.Errno:
		if errnoRet != nil {
			return libseccomp.ActErrno.SetReturnCode(int16(*errnoRet)), nil
		}
		return actErrno, nil
	case configs.Trap:
		return actTrap, nil
	case configs.Allow:
		return actAllow, nil
	case configs.Trace:
		if errnoRet != nil {
			return libseccomp.ActTrace.SetReturnCode(int16(*errnoRet)), nil
		}
		return actTrace, nil
	case configs.Log:
		return actLog, nil
	case configs.Notify:
		return actNotify, nil
	default:
		return libseccomp.ActInvalid, errors.New("invalid action, cannot use in rule")
	}
}

// Convert Libcontainer Operator to Libseccomp ScmpCompareOp
func getOperator(op configs.Operator) (libseccomp.ScmpCompareOp, error) {
	switch op {
	case configs.EqualTo:
		return libseccomp.CompareEqual, nil
	case configs.NotEqualTo:
		return libseccomp.CompareNotEqual, nil
	case configs.GreaterThan:
		return libseccomp.CompareGreater, nil
	case configs.GreaterThanOrEqualTo:
		return libseccomp.CompareGreaterEqual, nil
	case configs.LessThan:
		return libseccomp.CompareLess, nil
	case configs.LessThanOrEqualTo:
		return libseccomp.CompareLessOrEqual, nil
	case configs.MaskEqualTo:
		return libseccomp.CompareMaskedEqual, nil
	default:
		return libseccomp.CompareInvalid, errors.New("invalid operator, cannot use in rule")
	}
}

// Convert Libcontainer Arg to Libseccomp ScmpCondition
func getCondition(arg *configs.Arg) (libseccomp.ScmpCondition, error) {
	cond := libseccomp.ScmpCondition{}

	if arg == nil {
		return cond, errors.New("cannot convert nil to syscall condition")
	}

	op, err := getOperator(arg.Op)
	if err != nil {
		return cond, err
	}

	return libseccomp.MakeCondition(arg.Index, op, arg.Value, arg.ValueTwo)
}

// Add a rule to match a single syscall
func matchCall(filter *libseccomp.ScmpFilter, call *configs.Syscall) error {
	if call == nil || filter == nil {
		return errors.New("cannot use nil as syscall to block")
	}

	if len(call.Name) == 0 {
		return errors.New("empty string is not a valid syscall")
	}

	// If we can't resolve the syscall, assume it's not supported on this kernel
	// Ignore it, don't error out
	callNum, err := libseccomp.GetSyscallFromName(call.Name)
	if err != nil {
		return nil
	}

	// Convert the call's action to the libseccomp equivalent
	callAct, err := getAction(call.Action, call.ErrnoRet)
	if err != nil {
		return fmt.Errorf("action in seccomp profile is invalid: %s", err)
	}

	// Unconditional match - just add the rule
	if len(call.Args) == 0 {
		if err = filter.AddRule(callNum, callAct); err != nil {
			return fmt.Errorf("error adding seccomp filter rule for syscall %s: %s", call.Name, err)
		}
	} else {
		// If two or more arguments have the same condition, revert to old behavior, adding
		// each condition as a separate rule
		argCounts := make([]uint, syscallMaxArguments)
		conditions := []libseccomp.ScmpCondition{}

		for _, cond := range call.Args {
			newCond, err := getCondition(cond)
			if err != nil {
				return fmt.Errorf("error creating seccomp syscall condition for syscall %s: %s", call.Name, err)
			}

			argCounts[cond.Index] += 1

			conditions = append(conditions, newCond)
		}

		hasMultipleArgs := false
		for _, count := range argCounts {
			if count > 1 {
				hasMultipleArgs = true
				break
			}
		}

		if hasMultipleArgs {
			// Revert to old behavior
			// Add each condition attached to a separate rule
			for _, cond := range conditions {
				condArr := []libseccomp.ScmpCondition{cond}

				if err = filter.AddRuleConditional(callNum, callAct, condArr); err != nil {
					return fmt.Errorf("error adding seccomp rule for syscall %s: %s", call.Name, err)
				}
			}
		} else {
			// No conditions share same argument
			// Use new, proper behavior
			if err = filter.AddRuleConditional(callNum, callAct, conditions); err != nil {
				return fmt.Errorf("error adding seccomp rule for syscall %s: %s", call.Name, err)
			}
		}
	}

	return nil
}

func parseStatusFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	status := make(map[string]string)

	for s.Scan() {
		text := s.Text()
		parts := strings.Split(text, ":")

		if len(parts) <= 1 {
			continue
		}

		status[parts[0]] = parts[1]
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	return status, nil
}

// Version returns major, minor, and micro.
func Version() (uint, uint, uint) {
	return libseccomp.GetLibraryVersion()
}

// prepNotify prepares seccomp for syscall notification actions
func prepNotify(filter *libseccomp.ScmpFilter) error {

	// seccomp notification requires API level >= 5
	api, err := libseccomp.GetApi()
	if err != nil {
		return fmt.Errorf("error getting seccomp API level: %s", err)
	} else if api < 5 {
		err = libseccomp.SetApi(5)
		if err != nil {
			return fmt.Errorf("error setting seccomp API level to 5: %s", err)
		}
	}

	// seccomp notification is not compatible with thread-sync
	if err := filter.SetTsync(false); err != nil {
		return fmt.Errorf("Error clearing tsync on filter: %s", err)
	}

	return nil
}
