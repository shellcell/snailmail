package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/source"
)

const (
	doctorSchemaVersion        = 1
	maximumIndexBytes          = 2 << 20
	maximumDoctorArtifactBytes = 128 << 20
	maximumDoctorRunBytes      = 256 << 20
	maximumDoctorExpandedBytes = 64 << 20
)

type DoctorRequest struct {
	URL          string
	Format       string
	Project      string
	Suite        string
	Component    string
	Architecture string
	MaxArtifacts int
	Fetcher      source.Fetcher
	Now          time.Time
}

type DoctorResult struct {
	SchemaVersion    int             `json:"schema_version"`
	URL              string          `json:"url"`
	Format           string          `json:"format"`
	IndexURL         string          `json:"index_url"`
	Entries          int             `json:"entries"`
	ArtifactsChecked int             `json:"artifacts_checked"`
	Truncated        bool            `json:"truncated"`
	Findings         []DoctorFinding `json:"findings"`
}

type DoctorFinding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Subject  string `json:"subject"`
	Message  string `json:"message"`
}

type doctorIndexError struct{ err error }

func (err doctorIndexError) Error() string { return err.err.Error() }
func (err doctorIndexError) Unwrap() error { return err.err }

func Doctor(ctx context.Context, request DoctorRequest) (DoctorResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if request.Fetcher == nil {
		return DoctorResult{}, errors.New("doctor fetcher is required")
	}
	format := request.Format
	if format == "" {
		format = "auto"
	}
	if format != "auto" && format != "pypi" && format != "deb" && format != "helm" {
		return DoctorResult{}, errors.New("doctor format must be auto, pypi, deb, or helm")
	}
	if format == "auto" {
		switch {
		case request.Project != "":
			format = "pypi"
		case request.Suite != "":
			format = "deb"
		}
	}
	maximum := request.MaxArtifacts
	if maximum == 0 {
		maximum = 4
	}
	if maximum < 1 || maximum > 4 {
		return DoctorResult{}, errors.New("doctor max-artifacts must be between 1 and 4")
	}
	parsed, err := parseDoctorURL(request.URL)
	if err != nil {
		return DoctorResult{}, err
	}
	if request.Project == "" && (format == "auto" || format == "pypi") {
		request.Project = inferredPyPIProject(parsed.Path)
	}
	indexURL, err := doctorIndexURL(parsed, format, request)
	if err != nil {
		return DoctorResult{}, err
	}
	result := DoctorResult{SchemaVersion: doctorSchemaVersion, URL: parsed.String(), Format: format, IndexURL: indexURL.String(), Findings: make([]DoctorFinding, 0)}
	response, err := request.Fetcher.Fetch(ctx, indexURL.String(), maximumIndexBytes)
	if format == "auto" {
		if err == nil && response.StatusCode == http.StatusOK {
			format = detectDoctorFormat(indexURL.Path, response.ContentType, response.Body)
		}
		if format == "" || format == "auto" {
			candidate, candidateURL, candidateFormat, found, probeErr := probeDoctorConventional(ctx, request.Fetcher, parsed, request, indexURL.String())
			if probeErr != nil {
				return DoctorResult{}, probeErr
			}
			if found {
				response, indexURL, format, err = candidate, candidateURL, candidateFormat, nil
			}
		}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return DoctorResult{}, err
		}
		code, message := "index.unavailable", "repository index could not be observed"
		if errors.Is(err, source.ErrLimit) {
			code, message = "index.oversized", "repository index exceeds the doctor byte limit"
		}
		result.Findings = append(result.Findings, doctorError(code, result.IndexURL, message))
		return result, nil
	}
	if response.StatusCode != http.StatusOK {
		code, message := "index.unavailable", fmt.Sprintf("repository index returned HTTP %d", response.StatusCode)
		if response.StatusCode == 404 {
			code, message = "index.missing", "repository index returned HTTP 404"
		}
		result.Findings = append(result.Findings, doctorError(code, result.IndexURL, message))
		return result, nil
	}
	result.IndexURL = response.URL
	if result.IndexURL == "" {
		result.IndexURL = indexURL.String()
	} else if _, err := parseDoctorURL(result.IndexURL); err != nil {
		return DoctorResult{}, errors.New("repository fetcher returned an unsafe final URL")
	}
	if format == "" || format == "auto" {
		result.Findings = append(result.Findings, doctorError("index.unrecognized", result.IndexURL, "repository format could not be detected; use --format"))
		return result, nil
	}
	result.Format = format
	downloaded := int64(0)
	switch format {
	case "pypi":
		err = doctorPyPI(ctx, request, response, maximum, &downloaded, &result)
	case "deb":
		err = doctorDeb(ctx, request, response, maximum, &downloaded, &result)
	case "helm":
		err = doctorHelm(ctx, request, response, maximum, &downloaded, &result)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return DoctorResult{}, err
		}
		var indexErr doctorIndexError
		if errors.As(err, &indexErr) {
			result.Findings = append(result.Findings, doctorError("index.invalid", result.IndexURL, indexErr.Error()))
			sortDoctorFindings(result.Findings)
			return result, nil
		}
		return DoctorResult{}, err
	}
	if result.Truncated {
		result.Findings = append(result.Findings, DoctorFinding{Severity: "info", Code: "scope.truncated", Subject: result.IndexURL, Message: fmt.Sprintf("artifact inspection was limited to %d sorted references", maximum)})
	}
	sortDoctorFindings(result.Findings)
	return result, nil
}

func doctorPyPI(ctx context.Context, request DoctorRequest, response source.Response, maximum int, downloaded *int64, result *DoctorResult) error {
	if request.Project == "" {
		projects, err := pypi.ParseSimpleIndex(response.ContentType, response.Body)
		if err != nil {
			return doctorIndexError{err}
		}
		result.Entries = len(projects)
		result.Findings = append(result.Findings, DoctorFinding{Severity: "info", Code: "scope.project-required", Subject: result.IndexURL, Message: "project artifacts were not inspected; select one with --project"})
		return nil
	}
	pageName, files, err := pypi.ParseSimpleProject(response.ContentType, response.Body)
	if err != nil {
		return doctorIndexError{err}
	}
	if pageName != "" && pypi.NormalizeName(pageName) != pypi.NormalizeName(request.Project) {
		return doctorIndexError{errors.New("PyPI project page names a different project")}
	}
	result.Entries = len(files)
	sort.Slice(files, func(left, right int) bool {
		if files[left].Filename != files[right].Filename {
			return files[left].Filename < files[right].Filename
		}
		return files[left].URL < files[right].URL
	})
	supported := make([]pypi.SimpleFile, 0, len(files))
	unsupported := 0
	for _, file := range files {
		if file.Supported {
			supported = append(supported, file)
		} else {
			unsupported++
		}
	}
	if unsupported != 0 {
		result.Findings = append(result.Findings, DoctorFinding{Severity: "info", Code: "artifact.unsupported", Subject: result.IndexURL, Message: fmt.Sprintf("%d distribution files use formats unsupported for deep inspection", unsupported)})
	}
	if len(supported) > maximum {
		supported = supported[:maximum]
		result.Truncated = true
	}
	checkedBefore := result.ArtifactsChecked
	for _, file := range supported {
		if err := ctx.Err(); err != nil {
			return err
		}
		artifactURL, err := resolveDoctorReference(result.IndexURL, file.URL)
		if err != nil {
			result.Findings = append(result.Findings, doctorError("url.unsafe", file.Filename, err.Error()))
			continue
		}
		if file.SHA256 == "" {
			result.Findings = append(result.Findings, DoctorFinding{Severity: "warning", Code: "digest.unlisted", Subject: file.Filename, Message: "project page does not provide a SHA-256 fragment"})
		}
		content, ok, fetchErr := doctorFetchArtifact(ctx, request.Fetcher, artifactURL, pypi.MaxArtifactSize, file.Filename, downloaded, result)
		if fetchErr != nil {
			return fetchErr
		}
		if !ok {
			continue
		}
		result.ArtifactsChecked++
		if err := ctx.Err(); err != nil {
			return err
		}
		if file.SHA256 != "" && digest(content) != file.SHA256 {
			result.Findings = append(result.Findings, doctorError("digest.mismatch", file.Filename, "downloaded distribution does not match its listed SHA-256"))
			continue
		}
		facts, inspectErr := pypi.Inspect(file.Filename, bytes.NewReader(content), int64(len(content)))
		if inspectErr != nil {
			result.Findings = append(result.Findings, doctorError("artifact.invalid", file.Filename, inspectErr.Error()))
		} else if pypi.NormalizeName(facts.Name) != pypi.NormalizeName(request.Project) {
			result.Findings = append(result.Findings, doctorError("identity.mismatch", file.Filename, "distribution metadata names a different project"))
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	addDoctorInconclusive(checkedBefore, len(supported), result)
	return nil
}

func doctorHelm(ctx context.Context, request DoctorRequest, response source.Response, maximum int, downloaded *int64, result *DoctorResult) error {
	charts, err := helm.ParseRepositoryIndex(response.Body)
	if err != nil {
		return doctorIndexError{err}
	}
	result.Entries = len(charts)
	sort.Slice(charts, func(left, right int) bool {
		if charts[left].Name != charts[right].Name {
			return charts[left].Name < charts[right].Name
		}
		return charts[left].Version < charts[right].Version
	})
	if len(charts) > maximum {
		charts = charts[:maximum]
		result.Truncated = true
	}
	checkedBefore := result.ArtifactsChecked
	for _, chart := range charts {
		if err := ctx.Err(); err != nil {
			return err
		}
		subject := chart.Name + "@" + chart.Version
		content, artifactURL, ok, fetchErr := doctorFetchHelmChart(ctx, request.Fetcher, result.IndexURL, chart.URLs, subject, downloaded, result)
		if fetchErr != nil {
			return fetchErr
		}
		if !ok {
			continue
		}
		result.ArtifactsChecked++
		if err := ctx.Err(); err != nil {
			return err
		}
		if digest(content) != chart.Digest {
			result.Findings = append(result.Findings, doctorError("digest.mismatch", subject, "downloaded chart does not match its listed SHA-256"))
			continue
		}
		filename := path.Base(artifactURL.Path)
		facts, inspectErr := helm.InspectWithExpandedLimit(filename, bytes.NewReader(content), int64(len(content)), maximumDoctorExpandedBytes)
		if inspectErr != nil {
			result.Findings = append(result.Findings, doctorError("artifact.invalid", subject, inspectErr.Error()))
		} else if facts.Name != chart.Name || facts.Version != chart.Version {
			result.Findings = append(result.Findings, doctorError("identity.mismatch", subject, "chart metadata disagrees with index identity"))
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	addDoctorInconclusive(checkedBefore, len(charts), result)
	result.Findings = append(result.Findings, DoctorFinding{Severity: "info", Code: "signature.unverified", Subject: result.IndexURL, Message: "Helm provenance files were not verified"})
	return nil
}

func doctorFetchHelmChart(ctx context.Context, fetcher source.Fetcher, base string, references []string, subject string, downloaded *int64, result *DoctorResult) ([]byte, *url.URL, bool, error) {
	missing, unavailable := 0, 0
	for _, reference := range references {
		artifactURL, err := resolveDoctorReference(base, reference)
		if err != nil {
			result.Findings = append(result.Findings, doctorError("url.unsafe", subject, err.Error()))
			continue
		}
		remaining := int64(maximumDoctorRunBytes) - *downloaded
		maximum := int64(maximumDoctorArtifactBytes)
		if remaining < maximum {
			maximum = remaining
		}
		if maximum <= 0 {
			result.Findings = append(result.Findings, doctorError("scope.byte-limit", subject, "artifact inspection exceeded the cumulative byte limit"))
			return nil, nil, false, nil
		}
		*downloaded += maximum
		response, fetchErr := fetcher.Fetch(ctx, artifactURL.String(), maximum)
		if fetchErr != nil {
			if errors.Is(fetchErr, context.Canceled) || errors.Is(fetchErr, context.DeadlineExceeded) {
				return nil, nil, false, fetchErr
			}
			if errors.Is(fetchErr, source.ErrLimit) {
				result.Findings = append(result.Findings, doctorError("reference.oversized", subject, "referenced chart exceeds the doctor byte limit"))
			} else {
				unavailable++
			}
			continue
		}
		if int64(len(response.Body)) > maximum {
			result.Findings = append(result.Findings, doctorError("reference.oversized", subject, "referenced chart exceeds the doctor byte limit"))
			continue
		}
		if response.StatusCode == 404 {
			*downloaded -= maximum - int64(len(response.Body))
			missing++
			continue
		}
		if response.StatusCode != http.StatusOK {
			*downloaded -= maximum - int64(len(response.Body))
			unavailable++
			continue
		}
		*downloaded -= maximum - int64(len(response.Body))
		return response.Body, artifactURL, true, nil
	}
	if unavailable != 0 {
		result.Findings = append(result.Findings, DoctorFinding{Severity: "warning", Code: "reference.unavailable", Subject: subject, Message: "no listed chart URL could be observed"})
	} else if missing != 0 {
		result.Findings = append(result.Findings, doctorError("reference.missing", subject, "all listed chart URLs returned HTTP 404"))
	}
	return nil, nil, false, nil
}

func doctorDeb(ctx context.Context, request DoctorRequest, response source.Response, maximum int, downloaded *int64, result *DoctorResult) error {
	packagesContent := response.Body
	packagesURL := result.IndexURL
	packagesPath := strings.TrimSuffix(responseURLPath(result.IndexURL), "/")
	directPackages := strings.HasSuffix(packagesPath, "/Packages") || strings.HasSuffix(packagesPath, "/Packages.gz") || strings.HasSuffix(packagesPath, "/Packages.xz") || strings.HasSuffix(packagesPath, "/Packages.zst")
	if !directPackages {
		_, parseErr := deb.ParseRepositoryPackages(response.Body)
		directPackages = parseErr == nil
	}
	if !directPackages {
		release, err := deb.ParseRepositoryRelease(response.Body)
		if err != nil {
			return doctorIndexError{err}
		}
		now := request.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		if release.ValidUntil == "" {
			result.Findings = append(result.Findings, DoctorFinding{Severity: "warning", Code: "release.valid-until-missing", Subject: result.IndexURL, Message: "Debian Release has no Valid-Until field"})
		} else if validUntil, parseErr := http.ParseTime(release.ValidUntil); parseErr != nil {
			result.Findings = append(result.Findings, doctorError("release.valid-until-invalid", result.IndexURL, "Debian Release has an invalid Valid-Until field"))
		} else if !now.Before(validUntil) {
			result.Findings = append(result.Findings, doctorError("release.expired", result.IndexURL, "Debian Release metadata has expired"))
		}
		component := request.Component
		if component == "" && len(release.Components) != 0 {
			component = release.Components[0]
		}
		architecture := request.Architecture
		if architecture == "" && len(release.Architectures) != 0 {
			for _, candidate := range release.Architectures {
				if candidate != "all" {
					architecture = candidate
					break
				}
			}
			if architecture == "" {
				architecture = release.Architectures[0]
			}
		}
		wanted := component + "/binary-" + architecture + "/Packages"
		var listed *deb.ReleaseFile
		for _, suffix := range []string{"", ".xz", ".gz", ".zst"} {
			for index := range release.Files {
				if release.Files[index].Path == wanted+suffix {
					listed = &release.Files[index]
					break
				}
			}
			if listed != nil {
				break
			}
		}
		if listed == nil {
			return doctorIndexError{fmt.Errorf("Debian Release does not list %s", wanted)}
		}
		resolved, err := resolveDoctorReference(result.IndexURL, listed.Path)
		if err != nil {
			return doctorIndexError{err}
		}
		packagesResponse, err := request.Fetcher.Fetch(ctx, resolved.String(), 64<<20)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			code, message := "index.unavailable", "Debian Packages index could not be observed"
			if errors.Is(err, source.ErrLimit) {
				code, message = "index.oversized", "Debian Packages index exceeds the doctor byte limit"
			}
			result.Findings = append(result.Findings, doctorError(code, resolved.String(), message))
			return nil
		}
		if packagesResponse.StatusCode != 200 {
			code := "index.unavailable"
			if packagesResponse.StatusCode == 404 {
				code = "index.missing"
			}
			result.Findings = append(result.Findings, doctorError(code, resolved.String(), fmt.Sprintf("Debian Packages returned HTTP %d", packagesResponse.StatusCode)))
			return nil
		}
		if int64(len(packagesResponse.Body)) != listed.Size || digest(packagesResponse.Body) != listed.SHA256 {
			result.Findings = append(result.Findings, doctorError("index.digest-mismatch", resolved.String(), "Debian Packages does not match Release SHA-256 and size"))
			return nil
		}
		packagesContent, err = deb.DecompressRepositoryPackages(listed.Path, packagesResponse.Body)
		if err != nil {
			return doctorIndexError{fmt.Errorf("decompress Debian Packages: %w", err)}
		}
		packagesURL = packagesResponse.URL
		if packagesURL == "" {
			packagesURL = resolved.String()
		} else if _, err := parseDoctorURL(packagesURL); err != nil {
			return errors.New("repository fetcher returned an unsafe final Packages URL")
		}
		result.Findings = append(result.Findings, DoctorFinding{Severity: "warning", Code: "signature.unverified", Subject: result.IndexURL, Message: "Debian Release signature and key validity were not verified"})
	} else {
		var err error
		packagesContent, err = deb.DecompressRepositoryPackages(packagesPath, packagesContent)
		if err != nil {
			return doctorIndexError{fmt.Errorf("decompress Debian Packages: %w", err)}
		}
		result.Findings = append(result.Findings, DoctorFinding{Severity: "warning", Code: "signature.unverified", Subject: result.IndexURL, Message: "direct Packages inspection did not verify Release binding, signature, or key validity"})
	}
	packages, err := deb.ParseRepositoryPackages(packagesContent)
	if err != nil {
		return doctorIndexError{err}
	}
	result.Entries = len(packages)
	sort.Slice(packages, func(left, right int) bool {
		if packages[left].Package != packages[right].Package {
			return packages[left].Package < packages[right].Package
		}
		if packages[left].Version != packages[right].Version {
			return packages[left].Version < packages[right].Version
		}
		return packages[left].Architecture < packages[right].Architecture
	})
	if len(packages) > maximum {
		packages = packages[:maximum]
		result.Truncated = true
	}
	checkedBefore := result.ArtifactsChecked
	base, err := debRepositoryBase(packagesURL)
	if err != nil {
		result.Findings = append(result.Findings, DoctorFinding{Severity: "warning", Code: "scope.repository-base", Subject: packagesURL, Message: "pool artifacts were not inspected because repository base could not be inferred"})
		addDoctorInconclusive(result.ArtifactsChecked, len(packages), result)
		return nil
	}
	for _, packageRecord := range packages {
		artifactURL, err := resolveDoctorReference(base.String(), packageRecord.Filename)
		subject := packageRecord.Package + "@" + packageRecord.Version + "/" + packageRecord.Architecture
		if err != nil {
			result.Findings = append(result.Findings, doctorError("url.unsafe", subject, err.Error()))
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		content, ok, fetchErr := doctorFetchArtifact(ctx, request.Fetcher, artifactURL, deb.MaxArtifactSize, subject, downloaded, result)
		if fetchErr != nil {
			return fetchErr
		}
		if !ok {
			continue
		}
		result.ArtifactsChecked++
		if err := ctx.Err(); err != nil {
			return err
		}
		if int64(len(content)) != packageRecord.Size {
			result.Findings = append(result.Findings, doctorError("size.mismatch", subject, "downloaded package does not match its listed size"))
			continue
		}
		if digest(content) != packageRecord.SHA256 {
			result.Findings = append(result.Findings, doctorError("digest.mismatch", subject, "downloaded package does not match its listed SHA-256"))
			continue
		}
		facts, inspectErr := deb.InspectWithExpandedLimit(path.Base(packageRecord.Filename), bytes.NewReader(content), int64(len(content)), maximumDoctorExpandedBytes)
		if inspectErr != nil {
			result.Findings = append(result.Findings, doctorError("artifact.invalid", subject, inspectErr.Error()))
		} else if facts.Name != packageRecord.Package || facts.Version != packageRecord.Version || facts.Architecture != packageRecord.Architecture {
			result.Findings = append(result.Findings, doctorError("identity.mismatch", subject, "package control metadata disagrees with Packages index"))
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	addDoctorInconclusive(checkedBefore, len(packages), result)
	return nil
}

func addDoctorInconclusive(checkedBefore, references int, result *DoctorResult) {
	if references > 0 && result.ArtifactsChecked == checkedBefore {
		result.Findings = append(result.Findings, doctorError("scope.inconclusive", result.IndexURL, "none of the selected artifact references could be checked"))
	}
}

func doctorFetchArtifact(ctx context.Context, fetcher source.Fetcher, artifactURL *url.URL, maximum int64, subject string, downloaded *int64, result *DoctorResult) ([]byte, bool, error) {
	remaining := int64(maximumDoctorRunBytes) - *downloaded
	if maximum > maximumDoctorArtifactBytes {
		maximum = maximumDoctorArtifactBytes
	}
	if maximum > remaining {
		maximum = remaining
	}
	if maximum <= 0 {
		result.Findings = append(result.Findings, doctorError("scope.byte-limit", subject, "artifact inspection exceeded the cumulative byte limit"))
		return nil, false, nil
	}
	*downloaded += maximum
	response, err := fetcher.Fetch(ctx, artifactURL.String(), maximum)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, err
		}
		if errors.Is(err, source.ErrLimit) {
			result.Findings = append(result.Findings, doctorError("reference.oversized", subject, "referenced artifact exceeds the doctor byte limit"))
			return nil, false, nil
		}
		result.Findings = append(result.Findings, DoctorFinding{Severity: "warning", Code: "reference.unavailable", Subject: subject, Message: "referenced artifact could not be observed"})
		return nil, false, nil
	}
	if int64(len(response.Body)) > maximum {
		result.Findings = append(result.Findings, doctorError("reference.oversized", subject, "referenced artifact exceeds the doctor byte limit"))
		return nil, false, nil
	}
	if response.StatusCode == 404 {
		*downloaded -= maximum - int64(len(response.Body))
		result.Findings = append(result.Findings, doctorError("reference.missing", subject, "referenced artifact returned HTTP 404"))
		return nil, false, nil
	}
	if response.StatusCode != http.StatusOK {
		*downloaded -= maximum - int64(len(response.Body))
		result.Findings = append(result.Findings, DoctorFinding{Severity: "warning", Code: "reference.unavailable", Subject: subject, Message: fmt.Sprintf("referenced artifact returned HTTP %d", response.StatusCode)})
		return nil, false, nil
	}
	*downloaded -= maximum - int64(len(response.Body))
	return response.Body, true, nil
}

func doctorIndexURL(base *url.URL, format string, request DoctorRequest) (*url.URL, error) {
	value := *base
	clean := strings.TrimSuffix(value.Path, "/")
	switch format {
	case "pypi":
		if request.Project != "" {
			if !safeDoctorSegment(pypi.NormalizeName(request.Project)) {
				return nil, errors.New("doctor PyPI project must be one safe path segment")
			}
			project := pypi.NormalizeName(request.Project)
			if marker := strings.Index(clean+"/", "/simple/"); marker >= 0 {
				value.Path = clean[:marker] + "/simple/" + project + "/"
			} else {
				value.Path = strings.TrimSuffix(clean, "/simple") + "/simple/" + project + "/"
			}
		} else if !strings.HasSuffix(clean, "/simple") {
			value.Path = clean + "/simple/"
		}
	case "helm":
		if !strings.HasSuffix(clean, ".yaml") && !strings.HasSuffix(clean, ".yml") {
			value.Path = clean + "/index.yaml"
		}
	case "deb":
		for _, segment := range []string{request.Suite, request.Component, request.Architecture} {
			if segment != "" && !safeDoctorSegment(segment) {
				return nil, errors.New("doctor Debian selectors must be safe path segments")
			}
		}
		if !strings.HasSuffix(clean, "/Release") && !strings.HasSuffix(clean, "/Packages") && !strings.HasSuffix(clean, "/Packages.gz") && !strings.HasSuffix(clean, "/Packages.xz") && !strings.HasSuffix(clean, "/Packages.zst") {
			if request.Suite == "" {
				return nil, errors.New("doctor Debian base URL requires --suite or a concrete Release/Packages URL")
			}
			value.Path = clean + "/dists/" + request.Suite + "/Release"
		}
	}
	return &value, nil
}

func detectDoctorFormat(indexPath, contentType string, content []byte) string {
	clean := strings.TrimSuffix(indexPath, "/")
	switch {
	case strings.HasSuffix(clean, "index.yaml") || strings.HasSuffix(clean, "index.yml"):
		return "helm"
	case strings.HasSuffix(clean, "/Release") || strings.HasSuffix(clean, "/Packages") || strings.HasSuffix(clean, "/Packages.gz") || strings.HasSuffix(clean, "/Packages.xz") || strings.HasSuffix(clean, "/Packages.zst"):
		return "deb"
	case strings.Contains(clean, "/simple") || strings.Contains(strings.ToLower(contentType), "pypi"):
		return "pypi"
	}
	if _, err := helm.ParseRepositoryIndex(content); err == nil {
		return "helm"
	}
	if _, err := deb.ParseRepositoryPackages(content); err == nil {
		return "deb"
	}
	return ""
}

func probeDoctorConventional(ctx context.Context, fetcher source.Fetcher, base *url.URL, request DoctorRequest, excluded string) (source.Response, *url.URL, string, bool, error) {
	for _, candidateFormat := range []string{"pypi", "helm"} {
		candidateURL, err := doctorIndexURL(base, candidateFormat, request)
		if err != nil || candidateURL.String() == excluded {
			continue
		}
		candidate, err := fetcher.Fetch(ctx, candidateURL.String(), maximumIndexBytes)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return source.Response{}, nil, "", false, err
			}
			continue
		}
		if candidate.StatusCode != http.StatusOK {
			continue
		}
		valid := false
		switch candidateFormat {
		case "pypi":
			_, err = pypi.ParseSimpleIndex(candidate.ContentType, candidate.Body)
			valid = err == nil
		case "helm":
			_, err = helm.ParseRepositoryIndex(candidate.Body)
			valid = err == nil
		}
		if !valid {
			continue
		}
		if candidate.URL != "" {
			if _, err := parseDoctorURL(candidate.URL); err != nil {
				continue
			}
		}
		return candidate, candidateURL, candidateFormat, true, nil
	}
	return source.Response{}, nil, "", false, nil
}

func parseDoctorURL(raw string) (*url.URL, error) {
	value, err := url.Parse(raw)
	if err != nil || value.Scheme != "https" || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" || strings.ContainsAny(raw, "\x00\r\n\\") || strings.IndexFunc(value.Path, unicode.IsControl) >= 0 || strings.Contains(strings.ToLower(value.RawPath), "%2f") || strings.Contains(strings.ToLower(value.RawPath), "%5c") {
		return nil, errors.New("doctor URL must be an absolute HTTPS URL without credentials, query, fragment, or backslashes")
	}
	for _, segment := range strings.Split(value.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, errors.New("doctor URL must not contain dot segments")
		}
	}
	return value, nil
}

func safeDoctorSegment(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func inferredPyPIProject(value string) string {
	segments := strings.Split(strings.Trim(value, "/"), "/")
	for index := range segments {
		if segments[index] == "simple" && index+1 == len(segments)-1 && safeDoctorSegment(segments[index+1]) {
			return segments[index+1]
		}
	}
	return ""
}

func resolveDoctorReference(baseRaw, referenceRaw string) (*url.URL, error) {
	base, err := parseDoctorURL(baseRaw)
	if err != nil {
		return nil, err
	}
	reference, err := url.Parse(referenceRaw)
	if err != nil || reference.User != nil || reference.RawQuery != "" || strings.ContainsAny(referenceRaw, "\x00\r\n\\") {
		return nil, errors.New("repository reference URL is unsafe")
	}
	reference.Fragment = ""
	resolved := base.ResolveReference(reference)
	return parseDoctorURL(resolved.String())
}

func debRepositoryBase(raw string) (*url.URL, error) {
	value, err := parseDoctorURL(raw)
	if err != nil {
		return nil, err
	}
	marker := strings.Index(value.Path, "/dists/")
	if marker < 0 {
		value.Path = path.Dir(value.Path) + "/"
		return value, nil
	}
	value.Path = value.Path[:marker+1]
	return value, nil
}

func responseURLPath(raw string) string {
	value, _ := url.Parse(raw)
	return value.Path
}

func digest(content []byte) string {
	value := sha256.Sum256(content)
	return hex.EncodeToString(value[:])
}

func doctorError(code, subject, message string) DoctorFinding {
	return DoctorFinding{Severity: "error", Code: code, Subject: subject, Message: message}
}

func sortDoctorFindings(findings []DoctorFinding) {
	rank := map[string]int{"error": 0, "warning": 1, "info": 2}
	sort.Slice(findings, func(left, right int) bool {
		if rank[findings[left].Severity] != rank[findings[right].Severity] {
			return rank[findings[left].Severity] < rank[findings[right].Severity]
		}
		if findings[left].Code != findings[right].Code {
			return findings[left].Code < findings[right].Code
		}
		if findings[left].Subject != findings[right].Subject {
			return findings[left].Subject < findings[right].Subject
		}
		return findings[left].Message < findings[right].Message
	})
}
