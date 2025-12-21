// Package internxt provides an interface to Internxt's Drive API
package internxt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/internxt/rclone-adapter/buckets"
	config "github.com/internxt/rclone-adapter/config"
	"github.com/internxt/rclone-adapter/files"
	"github.com/internxt/rclone-adapter/folders"
	"github.com/internxt/rclone-adapter/users"
	"github.com/rclone/rclone/fs"
	rclone_config "github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/oauthutil"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/random"
)

const (
	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2 // bigger for slower decay, exponential
)

// shouldRetry determines if an error should be retried
func shouldRetry(ctx context.Context, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	return fserrors.ShouldRetry(err), err
}

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "internxt",
		Description: "Internxt Drive",
		NewFs:       NewFs,
		Config:      Config,
		Options: []fs.Option{
			{
				Name:       "token",
				Help:       "Internxt auth token (JWT).\n\nLeave blank to trigger interactive login.",
				IsPassword: true,
			},
			{
				Name:       "mnemonic",
				Help:       "Internxt encryption mnemonic.\n\nLeave blank to trigger interactive login.",
				IsPassword: true,
			},
			{
				Name:    "simulateEmptyFiles",
				Default: false,
				Help:    "Simulates empty files by uploading a small placeholder file instead. Alters the filename when uploading to keep track of empty files, but this is not visible through rclone.",
			},
			{
				Name:     "skipHashValidation",
				Default:  true,
				Advanced: true,
				Help:     "Skip hash validation when downloading files.\n\nBy default, hash validation is disabled. Set this to false to enable validation.",
			},
			{
				Name:     rclone_config.ConfigEncoding,
				Help:     rclone_config.ConfigEncodingHelp,
				Advanced: true,
				Default: encoder.EncodeInvalidUtf8 |
					encoder.EncodeSlash |
					encoder.EncodeBackSlash |
					encoder.EncodeRightPeriod |
					encoder.EncodeDot,
			},
		}},
	)
}

// Config implements the interactive configuration flow
func Config(ctx context.Context, name string, m configmap.Mapper, configIn fs.ConfigIn) (*fs.ConfigOut, error) {
	_, tokenOK := m.Get("token")
	mnemonic, mnemonicOK := m.Get("mnemonic")

	switch configIn.State {
	case "":
		// Check if we already have valid credentials
		if tokenOK && mnemonicOK && mnemonic != "" {
			// Get oauth2.Token from config
			oauthToken, err := oauthutil.GetToken(name, m)
			if err != nil {
				fs.Errorf(nil, "Failed to get token: %v", err)
				return fs.ConfigGoto("reauth")
			}

			if time.Until(oauthToken.Expiry) < tokenExpiry2d {
				fs.Logf(nil, "Token expires soon, attempting refresh...")
				err := refreshJWTToken(ctx, name, m)
				if err != nil {
					fs.Errorf(nil, "Failed to refresh token: %v", err)
					return fs.ConfigConfirm("reauth", true, "config_reauth",
						"Token refresh failed. Re-authenticate?")
				}
				fs.Logf(nil, "Token refreshed successfully")
				return nil, nil
			}

			return fs.ConfigConfirm("reauth", false, "config_reauth",
				"Already authenticated. Re-authenticate?")
		}

		return fs.ConfigGoto("auth")

	case "reauth":
		if configIn.Result == "false" {
			return nil, nil
		}
		return fs.ConfigGoto("auth")

	case "auth":
		newToken, newMnemonic, err := doAuth(ctx)
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}

		// Store mnemonic (obscured)
		m.Set("mnemonic", obscure.MustObscure(newMnemonic))

		// Store token in oauth2 format
		oauthToken, err := jwtToOAuth2Token(newToken)
		if err != nil {
			return nil, fmt.Errorf("failed to create oauth2 token: %w", err)
		}

		err = oauthutil.PutToken(name, m, oauthToken, true)
		if err != nil {
			return nil, fmt.Errorf("failed to save token: %w", err)
		}

		fs.Logf(nil, "")
		fs.Logf(nil, "Success! Authentication complete.")
		fs.Logf(nil, "")

		return nil, nil
	}

	return nil, fmt.Errorf("unknown state %q", configIn.State)
}

const (
	EMPTY_FILE_EXT = ".__RCLONE_EMPTY__"
)

var (
	EMPTY_FILE_BYTES = []byte{0x13, 0x09, 0x20, 0x23}
)

// Options holds configuration options for this interface
type Options struct {
	Token              string               `config:"token"`
	Mnemonic           string               `config:"mnemonic"`
	Encoding           encoder.MultiEncoder `config:"encoding"`
	SimulateEmptyFiles bool                 `config:"simulateEmptyFiles"`
	SkipHashValidation bool                 `config:"skipHashValidation"`
}

// Fs represents an Internxt remote
type Fs struct {
	name         string
	root         string
	opt          Options
	dirCache     *dircache.DirCache
	cfg          *config.Config
	features     *fs.Features
	pacer        *fs.Pacer
	tokenRenewer *oauthutil.Renew
	bridgeUser   string
	userID       string
}

// Object holds the data for a remote file object
type Object struct {
	f       *Fs
	remote  string
	id      string
	uuid    string
	size    int64
	modTime time.Time
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string { return f.name }

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string { return f.root }

// String converts this Fs to a string
func (f *Fs) String() string { return f.name + ":" + f.root }

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Hashes returns type of hashes supported by Internxt
func (f *Fs) Hashes() hash.Set {
	return hash.NewHashSet()
}

// Precision return the precision of this Fs
func (f *Fs) Precision() time.Duration {
	return fs.ModTimeNotSupported
}

// NewFs constructs an Fs from the path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return nil, err
	}

	if opt.Mnemonic == "" {
		return nil, errors.New("mnemonic is required - please run: rclone config reconnect " + name + ":")
	}

	// Reveal the obscured mnemonic
	var err error
	opt.Mnemonic, err = obscure.Reveal(opt.Mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to reveal mnemonic: %w", err)
	}

	oauthToken, err := oauthutil.GetToken(name, m)
	if err != nil {
		return nil, fmt.Errorf("failed to get token - please run: rclone config reconnect %s: - %w", name, err)
	}

	oauthConfig := &oauthutil.Config{
		TokenURL: "https://gateway.internxt.com/drive/users/refresh",
	}

	_, ts, err := oauthutil.NewClient(ctx, name, m, oauthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth client: %w", err)
	}

	cfg := config.NewDefaultToken(oauthToken.AccessToken)
	cfg.Mnemonic = opt.Mnemonic
	cfg.SkipHashValidation = opt.SkipHashValidation

	userInfo, err := getUserInfo(ctx, &userInfoConfig{Token: cfg.Token})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	cfg.RootFolderID = userInfo.RootFolderID
	cfg.Bucket = userInfo.Bucket
	cfg.BasicAuthHeader = computeBasicAuthHeader(userInfo.BridgeUser, userInfo.UserID)

	f := &Fs{
		name:       name,
		root:       strings.Trim(root, "/"),
		opt:        *opt,
		cfg:        cfg,
		bridgeUser: userInfo.BridgeUser,
		userID:     userInfo.UserID,
	}

	f.pacer = fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))

	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	if ts != nil {
		f.tokenRenewer = oauthutil.NewRenew(f.String(), ts, func() error {
			err := refreshJWTToken(ctx, name, m)
			if err != nil {
				return err
			}

			newToken, err := oauthutil.GetToken(name, m)
			if err != nil {
				return fmt.Errorf("failed to get refreshed token: %w", err)
			}
			f.cfg.Token = newToken.AccessToken
			f.cfg.BasicAuthHeader = computeBasicAuthHeader(f.bridgeUser, f.userID)

			return nil
		})
		f.tokenRenewer.Start()
	}

	f.dirCache = dircache.New(f.root, cfg.RootFolderID, f)

	err = f.dirCache.FindRoot(ctx, false)
	if err != nil {
		// Assume it might be a file
		newRoot, remote := dircache.SplitPath(f.root)
		tempF := *f
		tempF.dirCache = dircache.New(newRoot, f.cfg.RootFolderID, &tempF)
		tempF.root = newRoot

		err = tempF.dirCache.FindRoot(ctx, false)
		if err != nil {
			return f, nil
		}

		_, err := tempF.NewObject(ctx, remote)
		if err != nil {
			if err == fs.ErrorObjectNotFound {
				return f, nil
			}
			return nil, err
		}

		f.dirCache = tempF.dirCache
		f.root = tempF.root
		return f, fs.ErrorIsFile
	}

	return f, nil
}

// Mkdir creates a new directory
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	id, err := f.dirCache.FindDir(ctx, dir, true)
	if err != nil {
		return err
	}

	f.dirCache.Put(dir, id)

	return nil
}

// Rmdir removes a directory
// Returns an error if it isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	root := path.Join(f.root, dir)
	if root == "" {
		return errors.New("cannot remove root directory")
	}

	id, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return fs.ErrorDirNotFound
	}

	// Check if directory is empty
	var childFolders []folders.Folder
	err = f.pacer.Call(func() (bool, error) {
		var err error
		childFolders, err = folders.ListAllFolders(ctx, f.cfg, id)
		return shouldRetry(ctx, err)
	})
	if err != nil {
		return err
	}
	if len(childFolders) > 0 {
		return fs.ErrorDirectoryNotEmpty
	}

	var childFiles []folders.File
	err = f.pacer.Call(func() (bool, error) {
		var err error
		childFiles, err = folders.ListAllFiles(ctx, f.cfg, id)
		return shouldRetry(ctx, err)
	})
	if err != nil {
		return err
	}
	if len(childFiles) > 0 {
		return fs.ErrorDirectoryNotEmpty
	}

	// Delete the directory
	err = f.pacer.Call(func() (bool, error) {
		err := folders.DeleteFolder(ctx, f.cfg, id)
		if err != nil && strings.Contains(err.Error(), "404") {
			return false, fs.ErrorDirNotFound
		}
		return shouldRetry(ctx, err)
	})
	if err != nil {
		return err
	}

	f.dirCache.FlushDir(dir)
	return nil
}

// FindLeaf looks for a sub‑folder named `leaf` under the Internxt folder `pathID`.
// If found, it returns its UUID and true. If not found, returns "", false.
func (f *Fs) FindLeaf(ctx context.Context, pathID, leaf string) (string, bool, error) {
	entries, err := folders.ListAllFolders(ctx, f.cfg, pathID)
	if err != nil {
		return "", false, err
	}
	for _, e := range entries {
		if f.opt.Encoding.ToStandardName(e.PlainName) == leaf {
			return e.UUID, true, nil
		}
	}
	return "", false, nil
}

// CreateDir creates a new directory
func (f *Fs) CreateDir(ctx context.Context, pathID, leaf string) (string, error) {
	request := folders.CreateFolderRequest{
		PlainName:        f.opt.Encoding.FromStandardName(leaf),
		ParentFolderUUID: pathID,
		ModificationTime: time.Now().UTC().Format(time.RFC3339),
	}

	var resp *folders.Folder
	err := f.pacer.Call(func() (bool, error) {
		var err error
		resp, err = folders.CreateFolder(ctx, f.cfg, request)
		return shouldRetry(ctx, err)
	})
	if err != nil {
		return "", fmt.Errorf("can't create folder, %w", err)
	}

	return resp.UUID, nil
}

// preUploadCheck checks if a file exists in the given directory
// Returns the file metadata if it exists, nil if not
func (f *Fs) preUploadCheck(ctx context.Context, leaf, directoryID string) (*folders.File, error) {
	// Parse name and extension from the leaf
	baseName := f.opt.Encoding.FromStandardName(leaf)
	name := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	ext := strings.TrimPrefix(filepath.Ext(baseName), ".")

	checkResult, err := files.CheckFilesExistence(ctx, f.cfg, directoryID, []files.FileExistenceCheck{
		{
			PlainName:    name,
			Type:         ext,
			OriginalFile: struct{}{},
		},
	})

	if err != nil {
		// If existence check fails, assume file doesn't exist to allow upload to proceed
		return nil, nil
	}

	if len(checkResult.Files) > 0 && checkResult.Files[0].Exists {
		existingUUID := checkResult.Files[0].UUID
		if existingUUID != "" {
			fileMeta, err := files.GetFileMeta(ctx, f.cfg, existingUUID)
			if err == nil && fileMeta != nil {
				return convertFileMetaToFile(fileMeta), nil
			}

			if err != nil {
				return nil, err
			}
		}
	}

	return nil, nil
}

// convertFileMetaToFile converts files.FileMeta to folders.File
func convertFileMetaToFile(meta *files.FileMeta) *folders.File {
	// FileMeta and folders.File have compatible structures
	return &folders.File{
		ID:               meta.ID,
		UUID:             meta.UUID,
		FileID:           meta.FileID,
		PlainName:        meta.PlainName,
		Type:             meta.Type,
		Size:             meta.Size,
		Bucket:           meta.Bucket,
		FolderUUID:       meta.FolderUUID,
		EncryptVersion:   meta.EncryptVersion,
		ModificationTime: meta.ModificationTime,
	}
}

// List lists a directory
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	dirID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return nil, err
	}
	var out fs.DirEntries

	foldersList, err := folders.ListAllFolders(ctx, f.cfg, dirID)
	if err != nil {
		return nil, err
	}
	for _, e := range foldersList {
		remote := filepath.Join(dir, f.opt.Encoding.ToStandardName(e.PlainName))
		out = append(out, fs.NewDir(remote, e.ModificationTime))
	}
	filesList, err := folders.ListAllFiles(ctx, f.cfg, dirID)
	if err != nil {
		return nil, err
	}
	for _, e := range filesList {
		remote := e.PlainName
		if len(e.Type) > 0 {
			remote += "." + e.Type
		}
		remote = filepath.Join(dir, f.opt.Encoding.ToStandardName(remote))
		// If we found a file with the special empty file suffix, pretend that it's empty
		if f.opt.SimulateEmptyFiles && strings.HasSuffix(remote, EMPTY_FILE_EXT) {
			remote = strings.TrimSuffix(remote, EMPTY_FILE_EXT)
			e.Size = "0"
		}
		out = append(out, newObjectWithFile(f, remote, &e))
	}
	return out, nil
}

// Put uploads a file
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()
	leaf, directoryID, err := f.dirCache.FindPath(ctx, remote, false)
	if err != nil {
		if err == fs.ErrorDirNotFound {
			o := &Object{
				f:       f,
				remote:  remote,
				size:    src.Size(),
				modTime: src.ModTime(ctx),
			}
			return o, o.Update(ctx, in, src, options...)
		}
		return nil, err
	}

	// Check if file already exists
	existingFile, err := f.preUploadCheck(ctx, leaf, directoryID)
	if err != nil {
		return nil, err
	}

	// Create object - if file exists, populate it with existing metadata
	o := &Object{
		f:       f,
		remote:  remote,
		size:    src.Size(),
		modTime: src.ModTime(ctx),
	}

	if existingFile != nil {
		// File exists - populate object with existing metadata
		size, _ := existingFile.Size.Int64()
		o.id = existingFile.FileID
		o.uuid = existingFile.UUID
		o.size = size
		o.modTime = existingFile.ModificationTime
	}

	return o, o.Update(ctx, in, src, options...)
}

// Remove removes an object
func (f *Fs) Remove(ctx context.Context, remote string) error {
	obj, err := f.NewObject(ctx, remote)
	if err == nil {
		if err := obj.Remove(ctx); err != nil {
			return err
		}
		parent := path.Dir(remote)
		f.dirCache.FlushDir(parent)
		return nil
	}

	dirID, err := f.dirCache.FindDir(ctx, remote, false)
	if err != nil {
		return err
	}
	if err := folders.DeleteFolder(ctx, f.cfg, dirID); err != nil {
		return err
	}
	f.dirCache.FlushDir(remote)
	return nil
}

// NewObject creates a new object
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	parentDir := filepath.Dir(remote)

	if parentDir == "." {
		parentDir = ""
	}

	dirID, err := f.dirCache.FindDir(ctx, parentDir, false)
	if err != nil {
		return nil, fs.ErrorObjectNotFound
	}

	files, err := folders.ListAllFiles(ctx, f.cfg, dirID)
	if err != nil {
		return nil, err
	}
	for _, e := range files {
		name := e.PlainName
		if len(e.Type) > 0 {
			name += "." + e.Type
		}
		if f.opt.Encoding.ToStandardName(name) == filepath.Base(remote) {
			return newObjectWithFile(f, remote, &e), nil
		}
		// If we are simulating empty files, check for a file with the special suffix and if found return it as if empty.
		if f.opt.SimulateEmptyFiles {
			if f.opt.Encoding.ToStandardName(name) == filepath.Base(remote+EMPTY_FILE_EXT) {
				e.Size = "0"
				return newObjectWithFile(f, remote, &e), nil
			}
		}
	}
	return nil, fs.ErrorObjectNotFound
}

// newObjectWithFile returns a new object by file info
func newObjectWithFile(f *Fs, remote string, file *folders.File) fs.Object {
	size, _ := file.Size.Int64()
	return &Object{
		f:       f,
		remote:  remote,
		id:      file.FileID,
		uuid:    file.UUID,
		size:    size,
		modTime: file.ModificationTime,
	}
}

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.f
}

// String returns the remote path
func (o *Object) String() string {
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Size is the file length
func (o *Object) Size() int64 {
	return o.size
}

// ModTime is the last modified time (read-only)
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// Hash returns the hash value (not implemented)
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Storable returns if this object is storable
func (o *Object) Storable() bool {
	return true
}

// SetModTime sets the modified time
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorCantSetModTime
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	internxtLimit, err := users.GetLimit(ctx, f.cfg)
	if err != nil {
		return nil, err
	}

	internxtUsage, err := users.GetUsage(ctx, f.cfg)
	if err != nil {
		return nil, err
	}

	usage := &fs.Usage{
		Used: fs.NewUsageValue(internxtUsage.Drive),
	}

	usage.Total = fs.NewUsageValue(internxtLimit.MaxSpaceBytes)
	usage.Free = fs.NewUsageValue(*usage.Total - *usage.Used)

	return usage, nil
}

func (f *Fs) Shutdown(ctx context.Context) error {
	if f.tokenRenewer != nil {
		f.tokenRenewer.Shutdown()
	}
	return nil
}

// Open opens a file for streaming
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	fs.FixRangeOption(options, o.size)
	rangeValue := ""
	for _, option := range options {
		switch option.(type) {
		case *fs.RangeOption, *fs.SeekOption:
			_, rangeValue = option.Header()
		}
	}

	// Return nothing if we're faking an empty file
	if o.f.opt.SimulateEmptyFiles && o.size == 0 {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	return buckets.DownloadFileStream(ctx, o.f.cfg, o.id, rangeValue)
}

// Update updates an existing file or creates a new one
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	isEmptyFile := false
	remote := o.remote

	// Handle empty file simulation
	if src.Size() == 0 {
		if !o.f.opt.SimulateEmptyFiles {
			return fs.ErrorCantUploadEmptyFiles
		}
		// Simulate empty file with placeholder data and special suffix
		isEmptyFile = true
		in = bytes.NewReader(EMPTY_FILE_BYTES)
		src = &Object{
			f:       o.f,
			remote:  src.Remote() + EMPTY_FILE_EXT,
			modTime: src.ModTime(ctx),
			size:    int64(len(EMPTY_FILE_BYTES)),
		}
		remote = remote + EMPTY_FILE_EXT
	} else if o.f.opt.SimulateEmptyFiles {
		// Remove suffix if updating an empty file with actual data
		remote = strings.TrimSuffix(remote, EMPTY_FILE_EXT)
	}

	// Create directory if it doesn't exist
	_, dirID, err := o.f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return err
	}

	// === RENAME-BASED ROLLBACK PATTERN ===
	// This ensures data safety: old file is preserved until new upload succeeds

	var backupUUID string
	var backupName, backupType string
	oldUUID := o.uuid

	// Step 1: If file exists, rename to backup (preserves old file during upload)
	if oldUUID != "" {
		// Generate unique backup name
		baseName := filepath.Base(remote)
		name := strings.TrimSuffix(baseName, filepath.Ext(baseName))
		ext := strings.TrimPrefix(filepath.Ext(baseName), ".")

		backupSuffix := fmt.Sprintf(".rclone-backup-%s", random.String(8))
		backupName = o.f.opt.Encoding.FromStandardName(name + backupSuffix)
		backupType = ext

		// Rename existing file to backup name
		err = files.RenameFile(ctx, o.f.cfg, oldUUID, backupName, backupType)
		if err != nil {
			return fmt.Errorf("failed to rename existing file to backup: %w", err)
		}
		backupUUID = oldUUID

		fs.Debugf(o.f, "Renamed existing file %s to backup %s.%s (UUID: %s)", remote, backupName, backupType, backupUUID)
	}

	// Step 2: Upload new file to original location
	meta, err := buckets.UploadFileStreamAuto(ctx,
		o.f.cfg,
		dirID,
		o.f.opt.Encoding.FromStandardName(filepath.Base(remote)),
		in,
		src.Size(),
		src.ModTime(ctx),
	)

	if err != nil {
		// Upload failed - restore backup if it exists
		if backupUUID != "" {
			// Extract original name from remote
			origBaseName := filepath.Base(remote)
			origName := strings.TrimSuffix(origBaseName, filepath.Ext(origBaseName))
			origType := strings.TrimPrefix(filepath.Ext(origBaseName), ".")

			fs.Debugf(o.f, "Upload failed, attempting to restore backup %s.%s to %s", backupName, backupType, remote)

			restoreErr := files.RenameFile(ctx, o.f.cfg, backupUUID,
				o.f.opt.Encoding.FromStandardName(origName), origType)
			if restoreErr != nil {
				fs.Errorf(o.f, "CRITICAL: Upload failed AND backup restore failed: %v. Backup file remains as %s.%s (UUID: %s)",
					restoreErr, backupName, backupType, backupUUID)
				return fmt.Errorf("upload failed: %w (backup restore also failed: %v)", err, restoreErr)
			}
			fs.Debugf(o.f, "Upload failed, successfully restored backup file to original name")
		}
		return fmt.Errorf("upload failed: %w", err)
	}

	// Step 3: Upload succeeded - delete backup file
	if backupUUID != "" {
		fs.Debugf(o.f, "Upload succeeded, deleting backup %s.%s (UUID: %s)", backupName, backupType, backupUUID)

		if err := files.DeleteFile(ctx, o.f.cfg, backupUUID); err != nil {
			// Log warning but don't fail - new file is uploaded successfully
			// Backup file becomes orphaned but data integrity is maintained
			if !strings.Contains(err.Error(), "404") {
				fs.Logf(o.f, "Warning: uploaded new version but failed to delete backup %s.%s (UUID: %s): %v. You may need to manually delete this orphaned file.",
					backupName, backupType, backupUUID, err)
			}
		} else {
			fs.Debugf(o.f, "Successfully deleted backup file after upload")
		}
	}

	// Update object metadata
	o.uuid = meta.UUID
	o.size = src.Size()
	o.remote = remote
	// If this is a simulated empty file, set size to 0 for user-facing operations
	if isEmptyFile {
		o.size = 0
	}

	return nil
}

// Remove deletes a file
func (o *Object) Remove(ctx context.Context) error {
	return o.f.pacer.Call(func() (bool, error) {
		err := files.DeleteFile(ctx, o.f.cfg, o.uuid)
		return shouldRetry(ctx, err)
	})
}
