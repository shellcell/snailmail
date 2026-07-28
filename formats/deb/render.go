package deb

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

const FormatID = "deb/v1"

var coordinatePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

var supportedArchitectures = map[string]bool{
	"amd64": true, "arm64": true, "armhf": true, "armel": true,
	"i386": true, "mips64el": true, "ppc64el": true, "s390x": true,
}

type BuildOptions struct {
	Suite         string
	Component     string
	Architectures []string
	GeneratedAt   time.Time
}

type indexedBlob struct {
	blob     domain.Blob
	poolPath string
}

type releaseFile struct {
	path   string
	size   int
	md5    string
	sha1   string
	sha256 string
}

// Build renders deterministic unsigned apt metadata. The workspace engine may
// resolve and assemble repository-signing effects before finalization.
func Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	if !coordinatePattern.MatchString(options.Suite) || !coordinatePattern.MatchString(options.Component) {
		return domain.RepositoryArtifact{}, fmt.Errorf("suite and component must be safe path segments")
	}
	if options.GeneratedAt.IsZero() {
		return domain.RepositoryArtifact{}, fmt.Errorf("generation time is required")
	}
	architectures, err := normalizeArchitectures(options.Architectures)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	allowedArchitectures := make(map[string]bool, len(architectures))
	for _, architecture := range architectures {
		allowedArchitectures[architecture] = true
	}

	indexed := make([]indexedBlob, 0, len(blobs))
	poolDigests := make(map[string]string)
	identityDigests := make(map[string]string)
	for _, blob := range blobs {
		if err := validateBlob(blob); err != nil {
			return domain.RepositoryArtifact{}, err
		}
		if blob.Facts.Architecture != "all" && !allowedArchitectures[blob.Facts.Architecture] {
			return domain.RepositoryArtifact{}, fmt.Errorf("package %s has architecture %q outside the repository matrix", blob.Facts.Name, blob.Facts.Architecture)
		}
		poolPath := packagePoolPath(options.Component, blob)
		if previous := poolDigests[poolPath]; previous != "" && previous != blob.SHA256 {
			return domain.RepositoryArtifact{}, fmt.Errorf("different packages would occupy %q", poolPath)
		}
		identity := blob.Facts.Name + "\x00" + blob.Facts.Version + "\x00" + blob.Facts.Architecture
		if previous := identityDigests[identity]; previous != "" && previous != blob.SHA256 {
			return domain.RepositoryArtifact{}, fmt.Errorf("package identity %s@%s/%s is bound to different bytes", blob.Facts.Name, blob.Facts.Version, blob.Facts.Architecture)
		}
		poolDigests[poolPath] = blob.SHA256
		identityDigests[identity] = blob.SHA256
		indexed = append(indexed, indexedBlob{blob: blob, poolPath: poolPath})
	}
	sort.Slice(indexed, func(i, j int) bool {
		left, right := indexed[i].blob, indexed[j].blob
		if left.Facts.Name != right.Facts.Name {
			return left.Facts.Name < right.Facts.Name
		}
		if left.Facts.Version != right.Facts.Version {
			return left.Facts.Version < right.Facts.Version
		}
		if left.Facts.Architecture != right.Facts.Architecture {
			return left.Facts.Architecture < right.Facts.Architecture
		}
		return left.Filename < right.Filename
	})

	var files []domain.File
	seenPool := make(map[string]bool)
	for _, entry := range indexed {
		if seenPool[entry.poolPath] {
			continue
		}
		files = append(files, domain.File{
			Path:       entry.poolPath,
			Size:       entry.blob.Size,
			SHA256:     entry.blob.SHA256,
			BlobSHA256: entry.blob.SHA256,
		})
		seenPool[entry.poolPath] = true
	}

	var releaseFiles []releaseFile
	for _, architecture := range architectures {
		// Render straight into the buffer whose bytes become the file. Building a
		// string per stanza, copying it into an index builder and then copying
		// the whole index again to bytes held a large Packages index three times.
		var packages bytes.Buffer
		for _, entry := range indexed {
			if entry.blob.Facts.Architecture != "all" && entry.blob.Facts.Architecture != architecture {
				continue
			}
			writePackage(&packages, entry)
		}
		packagesBytes := packages.Bytes()
		base := path.Join("dists", options.Suite, options.Component, "binary-"+architecture)
		packagesPath := path.Join(base, "Packages")
		files = append(files, domain.File{Path: packagesPath, Content: packagesBytes})
		releaseFiles = append(releaseFiles, checksumFile(path.Join(options.Component, "binary-"+architecture, "Packages"), packagesBytes))

		compressed, err := gzipContent(packagesBytes, options.GeneratedAt)
		if err != nil {
			return domain.RepositoryArtifact{}, err
		}
		compressedPath := packagesPath + ".gz"
		files = append(files, domain.File{Path: compressedPath, Content: compressed})
		releaseFiles = append(releaseFiles, checksumFile(path.Join(options.Component, "binary-"+architecture, "Packages.gz"), compressed))

		binaryRelease := []byte(fmt.Sprintf("Archive: %s\nComponent: %s\nOrigin: snailmail\nLabel: snailmail\nArchitecture: %s\n", options.Suite, options.Component, architecture))
		binaryReleasePath := path.Join(base, "Release")
		files = append(files, domain.File{Path: binaryReleasePath, Content: binaryRelease})
		releaseFiles = append(releaseFiles, checksumFile(path.Join(options.Component, "binary-"+architecture, "Release"), binaryRelease))
	}
	sort.Slice(releaseFiles, func(i, j int) bool { return releaseFiles[i].path < releaseFiles[j].path })
	release := renderRelease(options, architectures, releaseFiles)
	files = append(files, domain.File{Path: path.Join("dists", options.Suite, "Release"), Content: release})

	verification := verificationCases(indexed, architectures)
	return domain.RepositoryArtifact{
		Format: FormatID,
		Files:  files,
		Install: domain.InstallSpec{
			Kind:          "deb",
			Suite:         options.Suite,
			Component:     options.Component,
			Architectures: append([]string(nil), architectures...),
		},
		VerificationCases: verification,
	}, nil
}

func normalizeArchitectures(input []string) ([]string, error) {
	seen := make(map[string]bool)
	var architectures []string
	for _, architecture := range input {
		architecture = strings.TrimSpace(architecture)
		if architecture == "" || architecture == "all" || !architecturePattern.MatchString(architecture) || !supportedArchitectures[architecture] {
			return nil, fmt.Errorf("invalid target architecture %q", architecture)
		}
		if !seen[architecture] {
			architectures = append(architectures, architecture)
			seen[architecture] = true
		}
	}
	if len(architectures) == 0 {
		return nil, fmt.Errorf("at least one target architecture is required")
	}
	sort.Strings(architectures)
	return architectures, nil
}

func validateBlob(blob domain.Blob) error {
	if !IsPackageFilename(blob.Filename) || !packagePattern.MatchString(blob.Facts.Name) || !architecturePattern.MatchString(blob.Facts.Architecture) || blob.Facts.Version == "" {
		return fmt.Errorf("Debian package %q has invalid package facts", blob.Filename)
	}
	if blob.Size < 0 || len(blob.MD5) != md5.Size*2 || len(blob.SHA1) != sha1.Size*2 || len(blob.SHA256) != sha256.Size*2 {
		return fmt.Errorf("Debian package %q has invalid size or checksums", blob.Filename)
	}
	for _, checksum := range []string{blob.MD5, blob.SHA1, blob.SHA256} {
		if _, err := hex.DecodeString(checksum); err != nil || checksum != strings.ToLower(checksum) {
			return fmt.Errorf("Debian package %q has an invalid checksum", blob.Filename)
		}
	}
	for field, expected := range map[string]string{"Package": blob.Facts.Name, "Version": blob.Facts.Version, "Architecture": blob.Facts.Architecture} {
		if blob.Facts.Fields[field] != expected {
			return fmt.Errorf("Debian package %q has inconsistent %s facts", blob.Filename, field)
		}
	}
	return nil
}

func packagePoolPath(component string, blob domain.Blob) string {
	prefix := blob.Facts.Name[:1]
	if strings.HasPrefix(blob.Facts.Name, "lib") && len(blob.Facts.Name) >= 4 {
		prefix = blob.Facts.Name[:4]
	}
	return path.Join("pool", component, prefix, blob.Facts.Name, blob.Filename)
}

func writePackage(output *bytes.Buffer, entry indexedBlob) {
	fields := make(map[string]string, len(entry.blob.Facts.Fields)+5)
	for name, value := range entry.blob.Facts.Fields {
		if name != "Status" && name != "Filename" && name != "Size" && name != "MD5sum" && name != "SHA1" && name != "SHA256" {
			fields[name] = value
		}
	}
	fields["Filename"] = entry.poolPath
	fields["Size"] = strconv.FormatInt(entry.blob.Size, 10)
	fields["MD5sum"] = entry.blob.MD5
	fields["SHA1"] = entry.blob.SHA1
	fields["SHA256"] = entry.blob.SHA256

	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		left, right := fieldRank(names[i]), fieldRank(names[j])
		if left != right {
			return left < right
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		writeField(output, name, fields[name])
	}
	output.WriteByte('\n')
}

func fieldRank(name string) int {
	order := []string{"Package", "Source", "Version", "Section", "Priority", "Architecture", "Essential", "Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances", "Breaks", "Conflicts", "Provides", "Replaces", "Installed-Size", "Maintainer", "Homepage", "Description", "Multi-Arch", "Built-Using", "Filename", "Size", "MD5sum", "SHA1", "SHA256"}
	for index, field := range order {
		if name == field {
			return index
		}
	}
	return len(order)
}

func writeField(output *bytes.Buffer, name, value string) {
	lines := strings.Split(value, "\n")
	output.WriteString(name)
	output.WriteString(": ")
	output.WriteString(lines[0])
	output.WriteByte('\n')
	for _, line := range lines[1:] {
		output.WriteByte(' ')
		if line == "" {
			output.WriteByte('.')
		} else {
			output.WriteString(line)
		}
		output.WriteByte('\n')
	}
}

func gzipContent(content []byte, generatedAt time.Time) ([]byte, error) {
	var buffer bytes.Buffer
	compressed, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	compressed.Header.ModTime = generatedAt.UTC()
	compressed.Header.OS = 255
	if _, err := compressed.Write(content); err != nil {
		return nil, err
	}
	if err := compressed.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func checksumFile(name string, content []byte) releaseFile {
	md5Value := md5.Sum(content)
	sha1Value := sha1.Sum(content)
	sha256Value := sha256.Sum256(content)
	return releaseFile{
		path:   name,
		size:   len(content),
		md5:    hex.EncodeToString(md5Value[:]),
		sha1:   hex.EncodeToString(sha1Value[:]),
		sha256: hex.EncodeToString(sha256Value[:]),
	}
}

func renderRelease(options BuildOptions, architectures []string, files []releaseFile) []byte {
	var release strings.Builder
	release.WriteString("Origin: snailmail\n")
	release.WriteString("Label: snailmail\n")
	release.WriteString("Suite: " + options.Suite + "\n")
	release.WriteString("Codename: " + options.Suite + "\n")
	release.WriteString("Date: " + options.GeneratedAt.UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC") + "\n")
	release.WriteString("Architectures: " + strings.Join(architectures, " ") + "\n")
	release.WriteString("Components: " + options.Component + "\n")
	release.WriteString("Description: generated by snailmail\n")
	for _, algorithm := range []string{"MD5Sum", "SHA1", "SHA256"} {
		release.WriteString(algorithm + ":\n")
		for _, file := range files {
			checksum := file.md5
			if algorithm == "SHA1" {
				checksum = file.sha1
			}
			if algorithm == "SHA256" {
				checksum = file.sha256
			}
			fmt.Fprintf(&release, " %s %d %s\n", checksum, file.size, file.path)
		}
	}
	return []byte(release.String())
}

func verificationCases(blobs []indexedBlob, architectures []string) []domain.VerificationCase {
	seen := make(map[string]bool)
	var cases []domain.VerificationCase
	for _, entry := range blobs {
		caseArchitectures := []string{entry.blob.Facts.Architecture}
		if entry.blob.Facts.Architecture == "all" {
			caseArchitectures = architectures
		}
		for _, architecture := range caseArchitectures {
			key := entry.blob.Facts.Name + "\x00" + entry.blob.Facts.Version + "\x00" + architecture
			if seen[key] {
				continue
			}
			seen[key] = true
			cases = append(cases, domain.VerificationCase{
				Package:      entry.blob.Facts.Name,
				Version:      entry.blob.Facts.Version,
				Architecture: architecture,
			})
		}
	}
	sort.Slice(cases, func(i, j int) bool {
		if cases[i].Package != cases[j].Package {
			return cases[i].Package < cases[j].Package
		}
		if cases[i].Version != cases[j].Version {
			return cases[i].Version < cases[j].Version
		}
		return cases[i].Architecture < cases[j].Architecture
	})
	return cases
}
