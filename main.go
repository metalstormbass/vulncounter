package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var containerList []string

type GrypeResult struct {
	Matches []Match `json:"matches"`
	Source  Source  `json:"source"`
}

type Match struct {
	Vulnerability          Vulnerability          `json:"vulnerability"`
	RelatedVulnerabilities []RelatedVulnerability `json:"relatedVulnerabilities"`
	MatchDetails           []MatchDetail          `json:"matchDetails"`
	Artifact               Artifact               `json:"artifact"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	Urls        []string `json:"urls"`
	Description string   `json:"description"`
	Cvss        []Cvss   `json:"cvss"`
	Fix         Fix      `json:"fix"`
}
type Cvss struct {
	Source         string                 `json:"source"`
	Type           string                 `json:"type"`
	Version        string                 `json:"version"`
	Vector         string                 `json:"vector"`
	Metrics        CvssMetrics            `json:"metrics"`
	VendorMetadata map[string]interface{} `json:"vendorMetadata"`
}

type CvssMetrics struct {
	BaseScore           float64 `json:"baseScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type CvssDetails struct {
	Source         string      `json:"source"`
	Type           string      `json:"type"`
	Version        string      `json:"version"`
	Vector         string      `json:"vector"`
	Metrics        CvssMetrics `json:"metrics"`
	VendorMetadata struct{}    `json:"vendorMetadata"`
}

type RelatedVulnerability struct {
	ID          string        `json:"id"`
	DataSource  string        `json:"dataSource"`
	Namespace   string        `json:"namespace"`
	URLs        []string      `json:"urls"`
	Description string        `json:"description"`
	Cvss        []CvssDetails `json:"cvss"`
}

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type MatchDetail struct {
	Type     string          `json:"type"`
	Matcher  string          `json:"matcher"`
	Searched SearchedDetails `json:"searchedBy"`
	Found    FoundDetails    `json:"found"`
}

type SearchedDetails struct {
	Language  string         `json:"language"`
	Namespace string         `json:"namespace"`
	Package   PackageDetails `json:"package"`
}

type PackageDetails struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type FoundDetails struct {
	VersionConstraint string `json:"versionConstraint"`
	VulnerabilityID   string `json:"vulnerabilityID"`
}

type Artifact struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Type      string        `json:"type"`
	Locations []Location    `json:"locations"`
	Language  string        `json:"language"`
	Licenses  []string      `json:"licenses"`
	Cpes      []string      `json:"cpes"`
	Purl      string        `json:"purl"`
	Upstreams []interface{} `json:"upstreams"`
}

type Location struct {
	Path    string `json:"path"`
	LayerID string `json:"layerID"`
}

type Source struct {
	Type   string `json:"type"`
	Target Target `json:"target"`
}

type Target struct {
	UserInput      string   `json:"userInput"`
	ImageID        string   `json:"imageID"`
	ManifestDigest string   `json:"manifestDigest"`
	MediaType      string   `json:"mediaType"`
	Tags           []string `json:"tags"`
	ImageSize      int      `json:"imageSize"`
	Layers         []Layer  `json:"layers"`
	Manifest       string   `json:"manifest"`
}

type Layer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

func main() {
	// Get File Name
	filename := os.Args[1]
	parse_txt(filename)

	for _, item := range containerList {
		image_name := item
		image_name = strings.ReplaceAll(image_name, " ", "")
		action := "pull"
		docker(image_name, action)

		action = "rmi"
		docker(image_name, action)

		grype(image_name)
	}
}

func grype(image_name string) {

	_, err := exec.LookPath("grype")
	if err != nil {
		fmt.Println("Error: The grype is not installed.")
		os.Exit(1)
	}

	cmd := exec.Command("grype", image_name, "-o json")

	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error running Grype: %v\n", err)
		//os.Exit(1)
		return
	}

	// Parse the JSON output
	severityCounts, err := parseGrypeJSON(string(output))
	if err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		return
	}

	fmt.Printf("Image Name: %s\n", image_name)

	severityLevels := []string{"Critical", "High", "Medium", "Low"}

	for _, severity := range severityLevels {
		count := severityCounts[severity]
		fmt.Printf("%s Vulnerabilities: %d\n", severity, count)
	}
	fmt.Println("")

}

func docker(image_name string, action string) {

	_, err := exec.LookPath("docker")
	if err != nil {
		fmt.Println("Error: The docker is not installed.")
		os.Exit(1)
	}

	cmd := exec.Command("docker", action, image_name)

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

}

func extractContainerInfo(line string) (string, error) {
	parts := strings.Split(line, ":")

	if len(parts) == 3 {
		returnpart := parts[1] + ":" + parts[2]
		return returnpart, nil

	} else {

		return parts[1], nil
	}

}

func parse_txt(filename string) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		containerInfo, err := extractContainerInfo(line)
		if err != nil {
			fmt.Println(err)
		} else {
			containerList = append(containerList, containerInfo)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}

}

func parseGrypeJSON(jsonData string) (map[string]int, error) {
	var result GrypeResult

	if err := json.Unmarshal([]byte(jsonData), &result); err != nil {
		return nil, err
	}

	severityCounts := make(map[string]int)

	for _, match := range result.Matches {
		severity := match.Vulnerability.Severity
		severityCounts[severity]++
	}

	return severityCounts, nil
}
