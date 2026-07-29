package rpm

import (
	"bytes"
	"fmt"
	"strconv"
	"time"
)

// The namespaces dnf expects. They are matched literally by some clients, so
// they are written exactly as createrepo does.
const (
	commonNamespace    = "http://linux.duke.edu/metadata/common"
	rpmNamespace       = "http://linux.duke.edu/metadata/rpm"
	filelistsNamespace = "http://linux.duke.edu/metadata/filelists"
	otherNamespace     = "http://linux.duke.edu/metadata/other"
	repoNamespace      = "http://linux.duke.edu/metadata/repo"
)

// renderPrimary writes the index describing every package: what it is, where it
// is, and what it needs. This is the one dnf reads to resolve and download.
func renderPrimary(entries []entry) ([]byte, error) {
	var document bytes.Buffer
	document.WriteString(xmlProlog)
	fmt.Fprintf(&document, "<metadata xmlns=%q xmlns:rpm=%q packages=\"%d\">\n",
		commonNamespace, rpmNamespace, len(entries))
	for _, item := range entries {
		pkg := item.pkg
		document.WriteString("<package type=\"rpm\">\n")
		fmt.Fprintf(&document, "  <name>%s</name>\n", escape(pkg.Name))
		fmt.Fprintf(&document, "  <arch>%s</arch>\n", escape(pkg.Architecture))
		fmt.Fprintf(&document, "  <version epoch=\"%d\" ver=%q rel=%q/>\n", pkg.Epoch, pkg.Version, pkg.Release)
		// pkgid marks this checksum as the package's identity, which is how dnf
		// ties an entry in this index to the file it downloads.
		fmt.Fprintf(&document, "  <checksum type=\"sha256\" pkgid=\"YES\">%s</checksum>\n", item.blob.SHA256)
		fmt.Fprintf(&document, "  <summary>%s</summary>\n", escape(pkg.Summary))
		fmt.Fprintf(&document, "  <description>%s</description>\n", escape(pkg.Description))
		fmt.Fprintf(&document, "  <packager>%s</packager>\n", escape(pkg.Packager))
		fmt.Fprintf(&document, "  <url>%s</url>\n", escape(pkg.URL))
		fmt.Fprintf(&document, "  <time file=\"%d\" build=\"%d\"/>\n", pkg.BuildTime, pkg.BuildTime)
		fmt.Fprintf(&document, "  <size package=\"%d\" installed=\"%d\" archive=\"%d\"/>\n",
			item.blob.Size, pkg.InstalledSize, pkg.InstalledSize)
		fmt.Fprintf(&document, "  <location href=%q/>\n", item.location)
		document.WriteString("  <format>\n")
		fmt.Fprintf(&document, "    <rpm:license>%s</rpm:license>\n", escape(pkg.License))
		fmt.Fprintf(&document, "    <rpm:vendor>%s</rpm:vendor>\n", escape(pkg.Vendor))
		fmt.Fprintf(&document, "    <rpm:group>%s</rpm:group>\n", escape(pkg.Group))
		fmt.Fprintf(&document, "    <rpm:buildhost>%s</rpm:buildhost>\n", escape(pkg.BuildHost))
		fmt.Fprintf(&document, "    <rpm:sourcerpm>%s</rpm:sourcerpm>\n", escape(pkg.SourceRPM))
		// The header range lets a client read a package's metadata without
		// fetching its payload.
		fmt.Fprintf(&document, "    <rpm:header-range start=\"%d\" end=\"%d\"/>\n", pkg.HeaderStart, pkg.HeaderEnd)
		writeDependencies(&document, "rpm:provides", pkg.Provides)
		writeDependencies(&document, "rpm:requires", pkg.Requires)
		document.WriteString("  </format>\n")
		document.WriteString("</package>\n")
	}
	document.WriteString("</metadata>\n")
	return document.Bytes(), nil
}

// writeDependencies emits a provides or requires block. rpmlib() entries are
// dropped: they constrain the rpm implementation rather than name a package,
// and dnf rejects a repository that offers them as ordinary requirements.
func writeDependencies(document *bytes.Buffer, element string, dependencies []Dependency) {
	usable := make([]Dependency, 0, len(dependencies))
	for _, dependency := range dependencies {
		if dependency.Name == "" || len(dependency.Name) > 4096 {
			continue
		}
		if element == "rpm:requires" && isImplementationRequirement(dependency.Name) {
			continue
		}
		usable = append(usable, dependency)
	}
	if len(usable) == 0 {
		return
	}
	fmt.Fprintf(document, "    <%s>\n", element)
	for _, dependency := range usable {
		fmt.Fprintf(document, "      <rpm:entry name=%q", escape(dependency.Name))
		if flag := comparisonFlag(dependency.Flags); flag != "" && dependency.Version != "" {
			epoch, version, release, err := splitEVR(dependency.Version)
			if err == nil {
				fmt.Fprintf(document, " flags=%q epoch=\"%d\" ver=%q", flag, epoch, version)
				if release != "" {
					fmt.Fprintf(document, " rel=%q", release)
				}
			}
		}
		document.WriteString("/>\n")
	}
	fmt.Fprintf(document, "    </%s>\n", element)
}

// isImplementationRequirement reports whether a dependency constrains rpm
// itself rather than naming a package that could satisfy it.
func isImplementationRequirement(name string) bool {
	return len(name) > 7 && name[:7] == "rpmlib(" && name[len(name)-1] == ')'
}

// RPM dependency comparison flags, from rpmds.h. The sense bits are the low
// four; everything above them describes where the dependency came from.
const (
	dependencyLess    = 0x02
	dependencyGreater = 0x04
	dependencyEqual   = 0x08
)

func comparisonFlag(flags int32) string {
	switch flags & (dependencyLess | dependencyGreater | dependencyEqual) {
	case dependencyLess:
		return "LT"
	case dependencyLess | dependencyEqual:
		return "LE"
	case dependencyGreater:
		return "GT"
	case dependencyGreater | dependencyEqual:
		return "GE"
	case dependencyEqual:
		return "EQ"
	default:
		return ""
	}
}

// renderFilelists writes the file index. It is emitted with no file entries:
// resolving a dependency on a path needs it, and snailmail does not read the
// cpio payload, so what it can honestly declare is which packages exist.
func renderFilelists(entries []entry) ([]byte, error) {
	var document bytes.Buffer
	document.WriteString(xmlProlog)
	fmt.Fprintf(&document, "<filelists xmlns=%q packages=\"%d\">\n", filelistsNamespace, len(entries))
	for _, item := range entries {
		fmt.Fprintf(&document, "<package pkgid=%q name=%q arch=%q>\n",
			item.blob.SHA256, escape(item.pkg.Name), escape(item.pkg.Architecture))
		fmt.Fprintf(&document, "  <version epoch=\"%d\" ver=%q rel=%q/>\n",
			item.pkg.Epoch, item.pkg.Version, item.pkg.Release)
		document.WriteString("</package>\n")
	}
	document.WriteString("</filelists>\n")
	return document.Bytes(), nil
}

// renderOther writes the changelog index, with no changelogs for the same
// reason: they live in the header and nothing here claims to have read them.
func renderOther(entries []entry) ([]byte, error) {
	var document bytes.Buffer
	document.WriteString(xmlProlog)
	fmt.Fprintf(&document, "<otherdata xmlns=%q packages=\"%d\">\n", otherNamespace, len(entries))
	for _, item := range entries {
		fmt.Fprintf(&document, "<package pkgid=%q name=%q arch=%q>\n",
			item.blob.SHA256, escape(item.pkg.Name), escape(item.pkg.Architecture))
		fmt.Fprintf(&document, "  <version epoch=\"%d\" ver=%q rel=%q/>\n",
			item.pkg.Epoch, item.pkg.Version, item.pkg.Release)
		document.WriteString("</package>\n")
	}
	document.WriteString("</otherdata>\n")
	return document.Bytes(), nil
}

// renderRepomd writes the document a client reads first: which indexes exist,
// where, and what they hash to. Everything else in the repository is reached
// through it, which is why it is the file a signature covers.
func renderRepomd(metadata []metadataFile, generatedAt time.Time) ([]byte, error) {
	var document bytes.Buffer
	document.WriteString(xmlProlog)
	fmt.Fprintf(&document, "<repomd xmlns=%q xmlns:rpm=%q>\n", repoNamespace, rpmNamespace)
	fmt.Fprintf(&document, "  <revision>%s</revision>\n", strconv.FormatInt(generatedAt.UTC().Unix(), 10))
	for _, file := range metadata {
		fmt.Fprintf(&document, "  <data type=%q>\n", file.kind)
		fmt.Fprintf(&document, "    <checksum type=\"sha256\">%s</checksum>\n", file.checksum)
		fmt.Fprintf(&document, "    <open-checksum type=\"sha256\">%s</open-checksum>\n", file.openChecksum)
		fmt.Fprintf(&document, "    <location href=%q/>\n", file.location)
		fmt.Fprintf(&document, "    <timestamp>%d</timestamp>\n", generatedAt.UTC().Unix())
		fmt.Fprintf(&document, "    <size>%d</size>\n", file.size)
		fmt.Fprintf(&document, "    <open-size>%d</open-size>\n", file.openSize)
		document.WriteString("  </data>\n")
	}
	document.WriteString("</repomd>\n")
	return document.Bytes(), nil
}

const xmlProlog = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
