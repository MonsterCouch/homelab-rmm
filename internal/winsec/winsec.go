// Package winsec holds the Windows access control the agent and the server
// both need on the directory they keep their secrets in. Both default to a
// child of %ProgramData%, which every local account may create, read and
// execute in, and where a Unix mode is a no-op - so the ACL is the whole of
// the protection.
//
// On every other platform the mode passed to MkdirAll already does the job
// and SecureDir is a no-op.
package winsec
