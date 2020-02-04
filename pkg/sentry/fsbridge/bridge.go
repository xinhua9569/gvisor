// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fsbridge

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// File provides a common interface to bridge between VFS1 and VFS2 files.
type File interface {
	// PathnameWithDeleted returns an absolute pathname to vd, consistent with
	// Linux's d_path(). In particular, if vd.Dentry() has been disowned,
	// PathnameWithDeleted appends " (deleted)" to the returned pathname.
	PathnameWithDeleted(ctx context.Context) string

	// ReadFull read all contents from the file.
	ReadFull(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error)

	// ConfigureMMap mutates opts to implement mmap(2) for the file.
	ConfigureMMap(context.Context, *memmap.MMapOpts) error

	// Type returns the file type, e.g. linux.DT_DIR.
	Type(context.Context) (uint8, error)

	IncRef()
	DecRef()

	// CheckPermissions checks that creds may access this inode for the requested
	// access type, per the the rules of fs/namei.c:generic_permission().
	CheckPermission(ctx context.Context, ats vfs.AccessTypes) error
}

// Lookup provides a common interface to open files.
type Lookup interface {
	// OpenPath opens a file.
	OpenPath(ctx context.Context, path string, ats vfs.AccessTypes, remainingTraversals *uint, resolveFinal bool) (File, error)
}
