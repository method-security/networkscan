package nuclei

import (
	// Standard
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"gopkg.in/yaml.v3"
)

// All is the CVE templates
//
//go:embed cve
var All embed.FS

// GetTemplateFileSystem returns filesystem views for templates based on the provided template paths.
// templatePaths can contain either:
// - Complete paths to template files (e.g., "cve/2024/CVE-2024-13624.yaml")
// - Folder paths (e.g., "cve/2024" or "cve") - will collect all .yaml/.yml files recursively from that folder
//
// protocol filters templates to only those whose info.metadata.protocol matches the given
// application protocol (e.g., "FTP", "SSH", "HTTP"). Pass an empty string to disable filtering.
func GetTemplateFileSystem(ctx context.Context, templatePaths []string, protocol string) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)

	if len(templatePaths) == 0 {
		return nil, fmt.Errorf("no template paths provided")
	}

	log.Info("Using template paths", svc1log.SafeParam("templatePaths", templatePaths))

	// Separate user-supplied OS paths from embedded-FS paths. A path is treated
	// as an OS path if it exists on disk; otherwise it is resolved against the
	// embedded CVE templates.
	var osFilesystems []fs.FS
	var embeddedPaths []string
	for _, templatePath := range templatePaths {
		// Treat the path as OS-supplied only when the caller wrote something that
		// clearly references the host filesystem. Bare relative paths like
		// "cve/2024" always resolve against the embedded archive — otherwise a
		// same-named directory in the working tree would silently shadow it.
		if !classifyTemplatePath(templatePath) {
			embeddedPaths = append(embeddedPaths, templatePath)
			continue
		}
		info, err := os.Stat(templatePath)
		if err != nil {
			log.Warn("User-supplied template path not found, skipping", svc1log.SafeParam("templatePath", templatePath), svc1log.SafeParam("error", err.Error()))
			continue
		}
		abs, absErr := filepath.Abs(templatePath)
		if absErr != nil {
			abs = templatePath
		}
		if info.IsDir() {
			count, walkErr := countTemplateFilesOnDisk(abs)
			if walkErr != nil {
				log.Warn("Failed to read user-supplied template directory, skipping", svc1log.SafeParam("templatePath", abs), svc1log.SafeParam("error", walkErr.Error()))
				continue
			}
			if count == 0 {
				log.Warn("User-supplied template directory contains no .yaml/.yml files, skipping", svc1log.SafeParam("templatePath", abs))
				continue
			}
			osFilesystems = append(osFilesystems, os.DirFS(abs))
			log.Info("Using user-supplied template directory", svc1log.SafeParam("templatePath", abs), svc1log.SafeParam("templateCount", count))
		} else if isTemplateFile(abs) {
			dir := filepath.Dir(abs)
			base := filepath.Base(abs)
			osFilesystems = append(osFilesystems, &singleFileFS{baseFS: os.DirFS(dir), name: base})
			log.Info("Using user-supplied template file", svc1log.SafeParam("templatePath", abs))
		} else {
			log.Warn("User-supplied path is not a yaml/yml template, skipping", svc1log.SafeParam("templatePath", abs))
		}
	}

	// Collect all template files from the embedded CVE FS
	var allTemplateFiles []string

	for _, templatePath := range embeddedPaths {
		// Clean the template path - normalize to cve/ prefix
		cleanPath := templatePath
		// Remove any leading slashes or dots
		cleanPath = strings.TrimPrefix(cleanPath, "./")
		cleanPath = strings.TrimPrefix(cleanPath, "/")

		// Ensure path starts with cve/
		if !strings.HasPrefix(cleanPath, "cve/") && !strings.HasPrefix(cleanPath, "cve") {
			cleanPath = filepath.Join("cve", cleanPath)
		}

		// Normalize the path
		cleanPath = filepath.Clean(cleanPath)

		// Check if this is a file or directory
		if isTemplateFile(cleanPath) {
			// It's a template file - verify it exists and add it
			if _, err := fs.Stat(All, cleanPath); err != nil {
				log.Warn("Template file not found, skipping", svc1log.SafeParam("templatePath", templatePath), svc1log.SafeParam("cleanPath", cleanPath), svc1log.SafeParam("error", err.Error()))
				continue
			}
			allTemplateFiles = append(allTemplateFiles, cleanPath)
		} else {
			// It's a directory - collect all template files recursively
			templates, err := collectTemplatesFromDirectory(cleanPath)
			if err != nil {
				log.Warn("Failed to collect templates from directory, skipping", svc1log.SafeParam("templatePath", templatePath), svc1log.SafeParam("cleanPath", cleanPath), svc1log.SafeParam("error", err.Error()))
				continue
			}
			allTemplateFiles = append(allTemplateFiles, templates...)
		}
	}

	if len(allTemplateFiles) == 0 && len(osFilesystems) == 0 {
		return nil, fmt.Errorf("no valid template files found")
	}

	// Apply protocol filtering if a protocol is specified
	if protocol != "" {
		beforeCount := len(allTemplateFiles)
		allTemplateFiles = filterTemplatesByProtocol(allTemplateFiles, protocol)
		log.Info("Filtered templates by protocol",
			svc1log.SafeParam("protocol", protocol),
			svc1log.SafeParam("beforeCount", beforeCount),
			svc1log.SafeParam("afterCount", len(allTemplateFiles)))

		if len(allTemplateFiles) == 0 {
			return nil, fmt.Errorf("no templates match protocol %q", protocol)
		}
	}

	log.Info("Found template files", svc1log.SafeParam("templateCount", len(allTemplateFiles)))

	// Group template files by their directory to create minimal filesystems
	dirToFiles := make(map[string][]string)

	for _, templateFile := range allTemplateFiles {
		templateDir := filepath.Dir(templateFile)
		templateName := filepath.Base(templateFile)
		dirToFiles[templateDir] = append(dirToFiles[templateDir], templateName)
	}

	var filesystems []fs.FS
	for templateDir, templateFiles := range dirToFiles {
		// Create a base filesystem for the directory
		baseFS, err := fs.Sub(All, templateDir)
		if err != nil {
			log.Warn("Template directory not found, skipping", svc1log.SafeParam("templateDir", templateDir), svc1log.SafeParam("error", err.Error()))
			continue
		}

		// Create a filtered filesystem that only exposes the specific template files
		filteredFS := &specificTemplateFS{
			baseFS:        baseFS,
			templateFiles: templateFiles,
		}

		filesystems = append(filesystems, filteredFS)
	}

	filesystems = append(filesystems, osFilesystems...)

	if len(filesystems) == 0 {
		return nil, fmt.Errorf("no valid template directories found")
	}

	return filesystems, nil
}

// singleFileFS exposes a single file from a base filesystem as if it were the
// only entry in the root directory. Used to wrap user-supplied template files
// so the nuclei runner can discover them via fs.WalkDir.
type singleFileFS struct {
	baseFS fs.FS
	name   string
}

func (s *singleFileFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &singleFileDir{fs: s}, nil
	}
	if name == s.name {
		return s.baseFS.Open(name)
	}
	return nil, fs.ErrNotExist
}

type singleFileDir struct {
	fs *singleFileFS
}

func (s *singleFileDir) Stat() (fs.FileInfo, error) { return &dirInfo{name: "."}, nil }
func (s *singleFileDir) Read([]byte) (int, error)   { return 0, fmt.Errorf("cannot read directory") }
func (s *singleFileDir) Close() error               { return nil }

func (s *singleFileDir) ReadDir(n int) ([]fs.DirEntry, error) {
	file, err := s.fs.baseFS.Open(s.fs.name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	entry := &fileDirEntry{
		name:    s.fs.name,
		size:    stat.Size(),
		mode:    stat.Mode(),
		modTime: stat.ModTime(),
	}
	entries := []fs.DirEntry{entry}
	if n > 0 && n < len(entries) {
		return entries[:n], nil
	}
	return entries, nil
}

// embeddedPathPrefixes are the top-level directories inside the bundled
// CVE template archive. A path beginning with one of these is always
// resolved against the embedded archive — never the host filesystem — so a
// same-named directory in the working tree cannot shadow bundled templates.
var embeddedPathPrefixes = []string{"cve/"}

// classifyTemplatePath returns true when the path should be resolved against
// the host filesystem rather than the embedded archive. The rules:
//
//   - Absolute paths and ./- / ../-prefixed paths are always OS paths.
//   - Paths starting with a known embedded prefix ("cve/") are always
//     embedded so internal callers' paths can never be shadowed by CWD.
//   - Any other relative path is treated as an OS path when it exists on
//     disk; otherwise the embedded resolver gets a chance to match it.
func classifyTemplatePath(p string) bool {
	if filepath.IsAbs(p) {
		return true
	}
	if strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") ||
		strings.HasPrefix(p, ".\\") || strings.HasPrefix(p, "..\\") {
		return true
	}
	for _, prefix := range embeddedPathPrefixes {
		if strings.HasPrefix(p, prefix) {
			return false
		}
	}
	if _, err := os.Stat(p); err == nil {
		return true
	}
	return false
}

// countTemplateFilesOnDisk counts .yaml/.yml files under dir (recursive).
func countTemplateFilesOnDisk(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if isTemplateFile(d.Name()) {
			count++
		}
		return nil
	})
	return count, err
}

// isTemplateFile checks if the given path appears to be a template file based on extension
func isTemplateFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// collectTemplatesFromDirectory recursively collects all .yaml and .yml files from the given directory
func collectTemplatesFromDirectory(dirPath string) ([]string, error) {
	var templates []string

	err := fs.WalkDir(All, dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Check if this is a template file
		if isTemplateFile(path) {
			templates = append(templates, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", dirPath, err)
	}

	return templates, nil
}

// specificTemplateFS wraps the base filesystem and only exposes specific template files
type specificTemplateFS struct {
	baseFS        fs.FS
	templateFiles []string
}

// Open implements fs.FS interface for the specific template filesystem.
func (s *specificTemplateFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &specificTemplateDir{fs: s}, nil
	}

	// Check if this file is one of the requested templates
	for _, templateFile := range s.templateFiles {
		if name == templateFile {
			return s.baseFS.Open(name)
		}
	}

	return nil, fs.ErrNotExist
}

// specificTemplateDir implements fs.ReadDirFile for directory listing
type specificTemplateDir struct {
	fs *specificTemplateFS
}

func (s *specificTemplateDir) Stat() (fs.FileInfo, error) {
	return &dirInfo{name: "."}, nil
}

func (s *specificTemplateDir) Read([]byte) (int, error) {
	return 0, fmt.Errorf("cannot read directory")
}

func (s *specificTemplateDir) Close() error {
	return nil
}

// ReadDir returns only the specific template files.
func (s *specificTemplateDir) ReadDir(n int) ([]fs.DirEntry, error) {
	var filteredEntries []fs.DirEntry

	for _, templateFile := range s.fs.templateFiles {
		// Try to get the file info
		file, err := s.fs.baseFS.Open(templateFile)
		if err != nil {
			continue
		}

		if stat, err := file.Stat(); err == nil {
			filteredEntries = append(filteredEntries, &fileDirEntry{
				name:    templateFile,
				size:    stat.Size(),
				mode:    stat.Mode(),
				modTime: stat.ModTime(),
			})
		}
		err = file.Close()
		if err != nil {
			continue
		}
	}

	if n <= 0 {
		return filteredEntries, nil
	}

	if n > len(filteredEntries) {
		n = len(filteredEntries)
	}

	return filteredEntries[:n], nil
}

// fileDirEntry implements fs.DirEntry for files
type fileDirEntry struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
}

func (f *fileDirEntry) Name() string               { return f.name }
func (f *fileDirEntry) IsDir() bool                { return false }
func (f *fileDirEntry) Type() fs.FileMode          { return f.mode.Type() }
func (f *fileDirEntry) Info() (fs.FileInfo, error) { return &fileInfo{f}, nil }

// fileInfo implements fs.FileInfo for files
type fileInfo struct {
	entry *fileDirEntry
}

func (f *fileInfo) Name() string       { return f.entry.name }
func (f *fileInfo) Size() int64        { return f.entry.size }
func (f *fileInfo) Mode() fs.FileMode  { return f.entry.mode }
func (f *fileInfo) ModTime() time.Time { return f.entry.modTime }
func (f *fileInfo) IsDir() bool        { return false }
func (f *fileInfo) Sys() interface{}   { return nil }

// dirInfo implements fs.FileInfo for directories
type dirInfo struct {
	name string
}

func (d *dirInfo) Name() string       { return d.name }
func (d *dirInfo) Size() int64        { return 0 }
func (d *dirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0755 }
func (d *dirInfo) ModTime() time.Time { return time.Time{} }
func (d *dirInfo) IsDir() bool        { return true }
func (d *dirInfo) Sys() interface{}   { return nil }

// filterTemplatesByProtocol returns only templates whose info.metadata.protocol
// matches the given protocol string (case-insensitive). Templates without a
// protocol field are excluded.
func filterTemplatesByProtocol(templateFiles []string, protocol string) []string {
	var matched []string
	for _, path := range templateFiles {
		tp := extractProtocol(path)
		if strings.EqualFold(tp, protocol) {
			matched = append(matched, path)
		}
	}
	return matched
}

// templateMetadata is the minimal structure needed to extract metadata from
// a Nuclei template. Using proper YAML parsing avoids issues with inline
// comments, quoting styles, and other YAML syntax that break naive string parsing.
type templateMetadata struct {
	Info struct {
		Metadata map[string]interface{} `yaml:"metadata"`
	} `yaml:"info"`
}

// extractProtocol reads a template file from the embedded FS and returns
// the value of the info.metadata.protocol field. Returns empty string if
// the field is not present or on any error.
func extractProtocol(templatePath string) string {
	data, err := fs.ReadFile(All, templatePath)
	if err != nil {
		return ""
	}

	var tmpl templateMetadata
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return ""
	}

	raw, ok := tmpl.Info.Metadata["protocol"]
	if !ok || raw == nil {
		return ""
	}

	return strings.TrimSpace(fmt.Sprintf("%v", raw))
}
