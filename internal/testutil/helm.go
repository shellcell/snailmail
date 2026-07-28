package testutil

import (
	"os"
	"path/filepath"
)

func HelmChart(name, version string) ([]byte, string, error) {
	chartYAML := "apiVersion: v2\n" +
		"name: " + name + "\n" +
		"version: " + version + "\n" +
		"appVersion: 2.4.6\n" +
		"description: deterministic test chart\n" +
		"type: application\n"
	return HelmChartWithMetadata(name, version, chartYAML)
}

func HelmChartWithMetadata(name, version, chartYAML string) ([]byte, string, error) {
	return helmChart(name, version, chartYAML, false)
}

// HelmChartWithArchiveRoot builds a chart whose archive leads with a "./"
// entry. `helm package` does not write one, but a chart rolled by hand with tar
// does, and it is not a reason to refuse the chart.
func HelmChartWithArchiveRoot(name, version string) ([]byte, string, error) {
	return helmChart(name, version, "apiVersion: v2\nname: "+name+"\nversion: "+version+
		"\nappVersion: 2.4.6\ndescription: deterministic test chart\ntype: application\n", true)
}

func helmChart(name, version, chartYAML string, rootEntry bool) ([]byte, string, error) {
	chart, err := tarGzip(map[string]string{
		name + "/Chart.yaml":  chartYAML,
		name + "/values.yaml": "message: relaxed delivery\n",
		name + "/templates/configmap.yaml": `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-{{ .Chart.Name }}
data:
  message: {{ .Values.message | quote }}
`,
	}, rootEntry)
	if err != nil {
		return nil, "", err
	}
	return chart, name + "-" + version + ".tgz", nil
}

func WriteHelmChart(directory, name, version string) (string, error) {
	content, filename, err := HelmChart(name, version)
	if err != nil {
		return "", err
	}
	filename = filepath.Join(directory, filename)
	if err := os.WriteFile(filename, content, 0o644); err != nil {
		return "", err
	}
	return filename, nil
}
