// By Pegleg <pegleg@linux.com>
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"compress/gzip"

	"github.com/buger/jsonparser"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/fatih/color"
	"github.com/moby/term"
)

const FilePerms = 0700

var filelist = flag.String("f", "", "File containing images to analyze seperated by line")
var verbose = flag.Bool("v", false, "Print all details about the image")
var filter = flag.Bool("filter", true, "Filters filenames that create noise such as"+
	" node_modules. Check ignore.go file for more details")
var extractLayers = flag.Bool("x", false, "Save layers to current directory")
var specificVersion = flag.String("sV", "", "Set the docker client ID to a specific version -sV=1.47")
var re *regexp.Regexp

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type ProgressDetail struct {
	Current int `json:"current"`
	Total   int `json:"total"`
}

type Status struct {
	Status         string         `json:"status"`
	ID             string         `json:"id"`
	ProgressDetail ProgressDetail `json:"progressDetail"`
}

type dockerHist struct {
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer"`
	LayerID    string
	Layers     []string
}

// DockerClient interface defines the methods we need from the Docker client
type DockerClient interface {
	ImageInspectWithRaw(ctx context.Context, imageID string) (image.InspectResponse, []byte, error)
	ImageSave(ctx context.Context, imageIDs []string, options ...client.ImageSaveOption) (io.ReadCloser, error)
	Close() error
}

// Add these new types for OCI format
type OCIIndex struct {
	Manifests []OCIManifest `json:"manifests"`
}

type OCIManifest struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

// Add a new struct for image config
type ImageConfig struct {
	Config struct {
		Env          []string               `json:"Env"`
		ExposedPorts map[string]interface{} `json:"ExposedPorts"`
		User         string                 `json:"User"`
	} `json:"config"`
	DockerVersion string `json:"docker_version"`
}

func printEnvironmentVariables(info image.InspectResponse) {
	if len(info.Config.Env) > 0 {
		color.White("Environment Variables")
		for _, ele := range info.Config.Env {
			color.Yellow("|%s", ele)
		}
		color.White("\n")
	}
}

func printPorts(info image.InspectResponse) {
	if len(info.Config.ExposedPorts) > 0 {
		color.White("Open Ports")
		for i := range info.Config.ExposedPorts {
			color.Green("|%s", i.Port())
		}
		color.White("\n")
	}
}

func printUserInfo(info image.InspectResponse) {
	color.White("Image user")
	if len(info.Config.User) == 0 {
		color.Red("|%s", "User is root")
	} else {
		color.Blue("|Image is running as User: %s", info.Config.User)
	}
	color.White("\n")
}

// New helper functions for ImageConfig
func printConfigEnvironmentVariables(env []string) {
	if len(env) > 0 {
		color.White("Environment Variables")
		for _, ele := range env {
			color.Yellow("|%s", ele)
		}
		color.White("\n")
	}
}

func printConfigPorts(ports map[string]interface{}) {
	if len(ports) > 0 {
		color.White("Open Ports")
		for port := range ports {
			color.Green("|%s", strings.TrimSuffix(port, "/tcp"))
		}
		color.White("\n")
	}
}

func printConfigUserInfo(user string) {
	color.White("Image user")
	if len(user) == 0 {
		color.Red("|%s", "User is root")
	} else {
		color.Blue("|Image is running as User: %s", user)
	}
	color.White("\n")
}

func analyze(cli DockerClient, imageID string) {
	info, _, err := cli.ImageInspectWithRaw(context.Background(), imageID)
	if err != nil {
		out, err := cli.ImageSave(context.Background(), []string{imageID})
		if err != nil {
			color.Red(err.Error())
			if strings.Contains(err.Error(), "Maximum supported API version is") {
				version := strings.Split(err.Error(), "Maximum supported API version is ")[1]
				color.Yellow("Use the -sV flag to change your client version:\n./whaler -sV=%s %s", version, imageID)
			}
			return
		}
		defer out.Close()
		fd, isTerminal := term.GetFdInfo(os.Stdout)
		if err := jsonmessage.DisplayJSONMessagesStream(out, os.Stdout, fd, isTerminal, nil); err != nil {
			fmt.Println(err)
		}
		info, _, err = cli.ImageInspectWithRaw(context.Background(), imageID)
		if err != nil {
			color.Red(err.Error())
			return
		}
	}
	color.White("Analyzing %s", imageID)
	color.White("Docker Version: %s", info.DockerVersion)
	color.White("GraphDriver: %s", info.GraphDriver.Name)
	printEnvironmentVariables(info)
	printPorts(info)
	printUserInfo(info)

	var result []dockerHist
	result, err = analyzeImageFilesystem(cli, imageID)
	if err != nil {
		color.Red("%s", err)
	}

	if *extractLayers && result != nil {
		imageStream, err := cli.ImageSave(context.Background(), []string{imageID})
		if err != nil {
			color.Red("%s", err)
			return
		}
		defer imageStream.Close()
		err = extractImageLayers(imageStream, imageID, result)
		if err != nil {
			color.Red("%s", err)
		}
	}
}

func analyzeSingleImage(cli DockerClient, imageID string) {
	analyze(cli, imageID)
}

func analyzeMultipleImages(cli DockerClient) {
	f, _ := os.Open(*filelist)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var imageIDs []string
	for scanner.Scan() {
		imageIDs = append(imageIDs, scanner.Text())
	}
	f.Close()
	for _, imageID := range imageIDs {
		analyzeSingleImage(cli, imageID)
	}
}

func extractImageLayers(imageStream io.ReadCloser, imageID string, history []dockerHist) error {
	var startAt = 1
	if *verbose {
		startAt = 0
	}
	outputDir := filepath.Join(".", url.QueryEscape(imageID))
	os.MkdirAll(outputDir, FilePerms)
	f, err := os.Create(filepath.Join(outputDir, "mapping.txt"))
	if err != nil {
		return err
	}
	var layersToExtract = make(map[string]int)

	for i := startAt; i < len(history); i++ {
		if strings.Contains(history[i].CreatedBy, "ADD") || strings.Contains(history[i].CreatedBy, "COPY") {
			layersToExtract[history[i].LayerID] = 1
			layerID := strings.Split(history[i].LayerID, "/")[0]
			f.WriteString(fmt.Sprintf("%s:%s\n", layerID, history[i].CreatedBy))
		}
	}
	f.Close()

	tr := tar.NewReader(imageStream)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if _, ok := layersToExtract[hdr.Name]; ok {
			layerID := strings.Split(hdr.Name, "/")[0]
			os.MkdirAll(filepath.Join(outputDir, layerID), FilePerms)
			ttr := tar.NewReader(tr)
			for {
				hdrr, err := ttr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					color.Red("%s", err)
				}
				name := hdrr.Name
				switch hdrr.Typeflag {
				case tar.TypeDir:
					os.MkdirAll(filepath.Join(outputDir, layerID, name), FilePerms)
				case tar.TypeReg:
					data := make([]byte, hdrr.Size)
					ttr.Read(data)
					os.WriteFile(filepath.Join(outputDir, layerID, name), data, FilePerms)
				}
			}
		}
	}
	return nil
}

// Update analyzeImage to better handle OCI format secret detection
func analyzeImage(imageStream io.ReadCloser, imageID string) ([]dockerHist, *ImageConfig, error) {
	defer imageStream.Close()

	tr := tar.NewReader(imageStream)
	var configs []Manifest
	var hist []dockerHist
	var layers = make(map[string][]string)
	var isOCIFormat bool
	var blobsFound []string
	var secretsFound bool

	var imgConfig *ImageConfig
	var ociBlobs = make(map[string][]byte)   // Store all blobs, not just tar files
	var ociConfigs = make(map[string][]byte) // Store config blobs specifically

	// First pass to determine format and read manifests
	for {
		imageFile, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		// Check if this is OCI format and collect all blobs
		if strings.HasPrefix(imageFile.Name, "blobs/sha256/") {
			isOCIFormat = true
			blobName := filepath.Base(imageFile.Name)
			blobsFound = append(blobsFound, blobName)

			// Read all blob data
			blobData, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read blob data: %v", err)
			}

			// Store JSON blobs separately for config processing
			if strings.HasSuffix(blobName, ".json") || containsJSON(blobData) {
				ociConfigs[blobName] = blobData
			}

			// Store all non-JSON blobs for layer processing
			if !strings.HasSuffix(blobName, ".json") {
				ociBlobs[blobName] = blobData
			}
			continue
		}

		// Handle config files and history (unchanged)
		if (!isOCIFormat && strings.Contains(imageFile.Name, ".json") && imageFile.Name != "manifest.json") ||
			(isOCIFormat && strings.HasPrefix(imageFile.Name, "blobs/sha256/")) {
			jsonBytes, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read config file: %v", err)
			}

			// Try to get history from the JSON
			h, dataType, _, err := jsonparser.Get(jsonBytes, "history")
			if err == nil && dataType == jsonparser.Array {
				if err := json.Unmarshal(h, &hist); err != nil {
					return nil, nil, fmt.Errorf("unable to parse history from json file: %v", err)
				}
			}

			// When handling config files, also try to parse image config
			var cfg ImageConfig
			if err := json.Unmarshal(jsonBytes, &cfg); err == nil {
				imgConfig = &cfg
			}
		}

		// Handle manifest files (unchanged)
		if imageFile.Name == "manifest.json" || imageFile.Name == "index.json" {
			byteValue, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read manifest file: %v", err)
			}

			if imageFile.Name == "index.json" {
				// Handle OCI format
				var index OCIIndex
				if err := json.Unmarshal(byteValue, &index); err != nil {
					return nil, nil, fmt.Errorf("unable to parse OCI index.json: %v", err)
				}
				// Convert OCI manifest to our format
				configs = []Manifest{{
					Config: strings.TrimPrefix(index.Manifests[0].Digest, "sha256:"),
					Layers: make([]string, 0),
				}}
				// We'll populate the layers later from the blobs
			} else {
				// Handle Docker format
				if err := json.Unmarshal(byteValue, &configs); err != nil {
					return nil, nil, fmt.Errorf("unable to parse manifest.json: %v", err)
				}
			}
		}

		// Handle layer files for non-OCI format (unchanged)
		if !isOCIFormat && strings.Contains(imageFile.Name, "layer.tar") {
			layerName := imageFile.Name
			ttr := tar.NewReader(tr)
			layers[layerName] = make([]string, 0)
			for {
				tarLayerFile, err := ttr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					color.Red("%s", err)
					continue
				}
				layers[layerName] = append(layers[layerName], tarLayerFile.Name)
				match := re.Find([]byte(tarLayerFile.Name))
				if match == nil {
					if !secretsFound {
						color.White("Potential secrets:")
						secretsFound = true
					}
					scanFilename(tarLayerFile.Name, layerName)
				}
			}
		}
	}

	// Process all OCI blobs, attempting to treat each as a potential layer
	if isOCIFormat {
		color.Yellow("Processing %d OCI blobs...", len(ociBlobs))

		// First, scan all blobs for secrets
		for blobName, blobData := range ociBlobs {
			// Try to process each blob as a potential layer
			layerReader := bytes.NewReader(blobData)

			// Try several approaches to read the blob
			layers[blobName] = make([]string, 0)
			var processed bool

			// Approach 1: Try as plain tar
			if !processed {
				tarReader := tar.NewReader(layerReader)
				if processLayerAsTar(tarReader, layers, blobName, &secretsFound) {
					processed = true
				}
				layerReader.Seek(0, io.SeekStart) // Reset for next attempt
			}

			// Approach 2: Try as gzipped tar - use standard gzip package
			if !processed {
				gzipReader, err := gzip.NewReader(layerReader)
				if err == nil {
					tarReader := tar.NewReader(gzipReader)
					if processLayerAsTar(tarReader, layers, blobName, &secretsFound) {
						processed = true
					}
					gzipReader.Close()                // Make sure to close the gzip reader
					layerReader.Seek(0, io.SeekStart) // Reset for next attempt
				}
			}

			// Approach 3: Try as raw content for secrets
			if !processed {
				// Scan the raw content for secrets
				rawContent := string(blobData)
				lines := strings.Split(rawContent, "\n")
				for _, line := range lines {
					match := re.Find([]byte(line))
					if match == nil && len(line) > 5 { // Skip very short lines
						if !secretsFound {
							color.White("Potential secrets:")
							secretsFound = true
						}
						scanFilename(line, blobName)
					}
				}
			}
		}
	}

	// For OCI format, specifically look for config with history
	if isOCIFormat && len(hist) == 0 {
		color.Yellow("Looking for history in OCI config files...")
		for blobName, jsonData := range ociConfigs {
			// Try to extract history from each config blob
			h, dataType, _, err := jsonparser.Get(jsonData, "history")
			if err == nil && dataType == jsonparser.Array {
				if err := json.Unmarshal(h, &hist); err == nil {
					color.Yellow("Found history in %s", blobName)
					break
				}
			}
		}

		// If still no history, try once more with a full JSON decode approach
		if len(hist) == 0 {
			for _, jsonData := range ociConfigs {
				var configObj map[string]interface{}
				if err := json.Unmarshal(jsonData, &configObj); err == nil {
					if historyArr, ok := configObj["history"].([]interface{}); ok {
						color.Yellow("Found %d history entries using alternate approach", len(historyArr))
						// Convert to our history format
						for _, item := range historyArr {
							if histItem, ok := item.(map[string]interface{}); ok {
								histEntry := dockerHist{}
								if created, ok := histItem["created"].(string); ok {
									histEntry.Created = created
								}
								if createdBy, ok := histItem["created_by"].(string); ok {
									histEntry.CreatedBy = createdBy
								}
								if emptyLayer, ok := histItem["empty_layer"].(bool); ok {
									histEntry.EmptyLayer = emptyLayer
								}
								hist = append(hist, histEntry)
							}
						}
						break
					}
				}
			}
		}
	}

	// If we still have no history in OCI format, generate a basic one
	if isOCIFormat && len(hist) == 0 {
		color.Yellow("No history found in image, generating basic history")
		// Create some placeholder history
		hist = append(hist, dockerHist{
			Created:   "unknown",
			CreatedBy: "FROM base image",
		})
	}

	// If this is OCI format, use the collected blobs
	if isOCIFormat && len(configs) > 0 {
		configs[0].Layers = blobsFound
	}

	// Map history to layers
	layerIndex := 0
	result := hist[:0]
	for _, i := range hist {
		if !i.EmptyLayer {
			if len(configs) > 0 && layerIndex < len(configs[0].Layers) {
				layerID := configs[0].Layers[layerIndex]
				if isOCIFormat {
					layerID = filepath.Base(layerID)
				}
				i.LayerID = layerID
				i.Layers = layers[layerID]
				layerIndex++
			}
			result = append(result, i)
		} else {
			// For OCI format, we still want to keep track of empty layers
			if isOCIFormat {
				result = append(result, i)
			} else {
				// Original behavior for non-OCI format
				result = append(result, i)
			}
		}
	}

	if isOCIFormat {
		color.Yellow("OCI format detected:")
		color.Yellow("Found %d history entries (%d non-empty)", len(hist), layerIndex)
		color.Yellow("Found %d layer files", len(configs[0].Layers))
		printResults(result)
		return result, imgConfig, nil
	}

	if layerIndex != len(configs[0].Layers) {
		return nil, nil, fmt.Errorf("layer mismatch: found %d layers but expected %d", layerIndex, len(configs[0].Layers))
	}

	printResults(result)
	return result, imgConfig, nil
}

// Helper function to check if a byte slice likely contains JSON
func containsJSON(data []byte) bool {
	// Simple check: if it starts with '{' and contains "config" or "history"
	if len(data) > 0 && data[0] == '{' {
		s := string(data[:min(200, len(data))])
		return strings.Contains(s, "\"config\"") ||
			strings.Contains(s, "\"history\"") ||
			strings.Contains(s, "\"rootfs\"")
	}
	return false
}

// Helper for min function (needed for Go < 1.21)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// New helper function to process a tar reader and extract layers
func processLayerAsTar(tarReader *tar.Reader, layers map[string][]string, layerName string, secretsFound *bool) bool {
	fileCount := 0

	for {
		fileHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Not a valid tar, don't report error but return false
			return false
		}

		fileCount++
		layers[layerName] = append(layers[layerName], fileHeader.Name)

		match := re.Find([]byte(fileHeader.Name))
		if match == nil {
			if !*secretsFound {
				color.White("Potential secrets:")
				*secretsFound = true
			}
			scanFilename(fileHeader.Name, layerName)
		}
	}

	return fileCount > 0 // Return true if we processed at least one file
}

// Update analyzeImageFilesystem to handle ImageConfig
func analyzeImageFilesystem(cli DockerClient, imageID string) ([]dockerHist, error) {
	imageStream, err := cli.ImageSave(context.Background(), []string{imageID})
	if err != nil {
		return nil, err
	}

	result, _, err := analyzeImage(imageStream, imageID)
	if err != nil {
		return nil, err
	}

	if *extractLayers && result != nil {
		// Need to get a fresh stream for layer extraction
		imageStream, err := cli.ImageSave(context.Background(), []string{imageID})
		if err != nil {
			return nil, err
		}
		defer imageStream.Close()

		err = extractImageLayers(imageStream, imageID, result)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Update analyzeFromTar to print info in the correct order
func analyzeFromTar(tarPath string) error {
	// Get the base name of the tar file to use as the image ID
	imageID := filepath.Base(tarPath)
	imageID = strings.TrimSuffix(imageID, filepath.Ext(imageID))

	// Print image name first
	color.White("Analyzing %s", imageID)

	// First pass just to get the config
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("failed to open tar file: %v", err)
	}

	// In this first pass, just get config without secrets or layers analysis
	config, err := extractImageConfig(io.NopCloser(f))
	if err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Print image information if available - this matches the Docker client order
	if config != nil {
		color.White("Docker Version: %s", config.DockerVersion)
		color.White("GraphDriver: overlay2") // Default for tar files

		if len(config.Config.Env) > 0 {
			printConfigEnvironmentVariables(config.Config.Env)
		}

		if len(config.Config.ExposedPorts) > 0 {
			printConfigPorts(config.Config.ExposedPorts)
		}

		printConfigUserInfo(config.Config.User)
	}

	// Second pass to do the full analysis
	f2, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("failed to reopen tar file: %v", err)
	}
	defer f2.Close()

	result, _, err := analyzeImage(io.NopCloser(f2), imageID)
	if err != nil {
		return err
	}

	if *extractLayers && result != nil {
		// Need to reopen the file for layer extraction
		extractFile, extractErr := os.Open(tarPath)
		if extractErr != nil {
			return fmt.Errorf("failed to reopen tar file: %v", extractErr)
		}
		defer extractFile.Close()

		err = extractImageLayers(io.NopCloser(extractFile), imageID, result)
		if err != nil {
			return err
		}
	}

	return nil
}

func printResults(layers []dockerHist) {
	color.White("Dockerfile:")
	if *verbose {
		for i := 0; i < len(layers); i++ {
			color.Green("%s\n", cleanString(layers[i].CreatedBy))
			for _, l := range layers[i].Layers {
				color.Blue("\t%s", l)
			}

		}
	} else {
		for i := 1; i < len(layers); i++ {
			color.Green("%s\n", cleanString(layers[i].CreatedBy))
			if strings.Contains(layers[i].CreatedBy, "ADD") || strings.Contains(layers[i].CreatedBy, "COPY") {
				for _, l := range layers[i].Layers {
					if *filter {
						match := re.Find([]byte(l))
						if match == nil {
							color.Green("\t%s", l)
						}
					} else {
						color.Green("\t%s", l)
					}
				}
				color.Green("")
			}

		}

	}
	color.White("")
}

func cleanString(str string) string {
	s := strings.Join(strings.Fields(str), " ")
	s = strings.Replace(s, "&&", "\\\n\t&&", -1)

	// Handle strings that start with /bin/sh -c
	if strings.HasPrefix(s, "/bin/sh -c ") {
		if strings.HasPrefix(s, "/bin/sh -c #(nop)") {
			// Non-operation commands (like LABEL, ENV, etc.)
			s = strings.Replace(s, "/bin/sh -c ", "", -1)
			s = strings.Replace(s, "#(nop) ", "", -1)
		} else {
			// RUN commands
			s = strings.Replace(s, "/bin/sh -c ", "RUN ", -1)
		}
	}

	// Check if the string already starts with RUN and has a duplicated /bin/sh -c
	if strings.HasPrefix(s, "RUN /bin/sh -c ") {
		s = strings.Replace(s, "RUN /bin/sh -c ", "RUN ", 1)
	}

	// Remove double RUN prefix if it exists
	if strings.HasPrefix(s, "RUN RUN ") {
		s = strings.Replace(s, "RUN RUN ", "RUN ", 1)
	}

	return s
}

// New function to just extract image config without full analysis
func extractImageConfig(imageStream io.ReadCloser) (*ImageConfig, error) {
	defer imageStream.Close()
	tr := tar.NewReader(imageStream)
	var imgConfig *ImageConfig
	var isOCIFormat bool

	for {
		imageFile, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Check if this is OCI format
		if strings.HasPrefix(imageFile.Name, "blobs/sha256/") {
			isOCIFormat = true
		}

		// Handle config files
		if (!isOCIFormat && strings.Contains(imageFile.Name, ".json") && imageFile.Name != "manifest.json") ||
			(isOCIFormat && strings.HasPrefix(imageFile.Name, "blobs/sha256/")) {
			jsonBytes, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file: %v", err)
			}

			// Try to parse image config
			var cfg ImageConfig
			if err := json.Unmarshal(jsonBytes, &cfg); err == nil {
				imgConfig = &cfg
				// Once we have the config, we can return
				if imgConfig.DockerVersion != "" && len(imgConfig.Config.Env) > 0 {
					return imgConfig, nil
				}
			}
		}
	}
	return imgConfig, nil
}

func main() {
	var cli DockerClient
	var err error
	var tarFile = flag.String("t", "", "Analyze a docker save tar file from disk")
	flag.Parse()
	re = regexp.MustCompile(strings.Join(InternalWordlist, "|"))
	compileSecretPatterns()

	// If tar file is specified, analyze it directly
	if len(*tarFile) > 0 {
		if err := analyzeFromTar(*tarFile); err != nil {
			color.Red("Error analyzing tar file: %v", err)
		}
		return
	}

	// Existing Docker client logic
	if len(*specificVersion) > 0 {
		cli, err = client.NewClientWithOpts(client.WithVersion(*specificVersion))
	} else {
		cli, err = client.NewClientWithOpts()
	}
	if err != nil {
		color.Red(err.Error())
		return
	}
	repo := flag.Arg(0)
	if len(*filelist) > 0 {
		analyzeMultipleImages(cli)
	} else if len(repo) > 0 {
		imageID := repo
		analyzeSingleImage(cli, imageID)
	} else {
		color.Red("Please provide a repository image to analyze. ./whaler nginx:latest")
		return
	}
	cli.Close()
}
