package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"archive/tar"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
)

// MockDockerClient implements a basic mock of the Docker client
type MockDockerClient struct {
	*client.Client
	imageInspectFunc func(ctx context.Context, imageID string) (image.InspectResponse, []byte, error)
	imageSaveFunc    func(ctx context.Context, imageIDs []string) (io.ReadCloser, error)
}

func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (image.InspectResponse, []byte, error) {
	if m.imageInspectFunc != nil {
		return m.imageInspectFunc(ctx, imageID)
	}
	return image.InspectResponse{}, nil, nil
}

func (m *MockDockerClient) ImageSave(ctx context.Context, imageIDs []string, options ...client.ImageSaveOption) (io.ReadCloser, error) {
	if m.imageSaveFunc != nil {
		return m.imageSaveFunc(ctx, imageIDs)
	}
	return nil, nil
}

func (m *MockDockerClient) Close() error {
	return nil
}

func TestCleanString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Basic RUN command",
			input:    "/bin/sh -c echo 'hello'",
			expected: "RUN echo 'hello'",
		},
		{
			name:     "NOP command",
			input:    "/bin/sh -c #(nop) ADD file:123 /app",
			expected: "ADD file:123 /app",
		},
		{
			name:     "Command with &&",
			input:    "cd /app && npm install",
			expected: "cd /app \\\n\t&& npm install",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractImageLayers(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "whaler-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a mock Docker client
	mockClient := &MockDockerClient{
		Client: &client.Client{},
		imageSaveFunc: func(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
			// Create a tar file in memory with our test data
			pr, pw := io.Pipe()
			go func() {
				tw := tar.NewWriter(pw)

				// Write a layer file
				layerContent := "test layer content"
				header := &tar.Header{
					Name: "layer1/test.txt",
					Size: int64(len(layerContent)),
					Mode: 0600,
				}
				tw.WriteHeader(header)
				tw.Write([]byte(layerContent))

				tw.Close()
				pw.Close()
			}()
			return pr, nil
		},
	}

	// Test the extractImageLayers function
	err = extractImageLayers(mockClient, "test-image", []dockerHist{
		{
			CreatedBy:  "ADD file:123 /app",
			LayerID:    "layer1",
			EmptyLayer: false,
		},
	})

	if err != nil {
		t.Errorf("extractImageLayers failed: %v", err)
	}

	// Verify that the output directory was created
	outputDir := filepath.Join(".", "test-image")
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		t.Error("Output directory was not created")
	}
}

func TestAnalyzeImageFilesystem(t *testing.T) {
	// Create test data
	testData := `{
		"history": [
			{
				"created": "2024-03-13T00:00:00Z",
				"created_by": "ADD file:123 /app",
				"empty_layer": false
			}
		]
	}`

	mockClient := &MockDockerClient{
		Client: &client.Client{},
		imageSaveFunc: func(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
			// Create a tar file in memory with our test data
			pr, pw := io.Pipe()
			go func() {
				tw := tar.NewWriter(pw)

				// Write the config file
				header := &tar.Header{
					Name: "test.json",
					Size: int64(len(testData)),
					Mode: 0600,
				}
				tw.WriteHeader(header)
				tw.Write([]byte(testData))

				// Write the manifest file with a layer
				manifest := `[{"Config":"test.json","RepoTags":["test-image:latest"],"Layers":["layer1.tar"]}]`
				header = &tar.Header{
					Name: "manifest.json",
					Size: int64(len(manifest)),
					Mode: 0600,
				}
				tw.WriteHeader(header)
				tw.Write([]byte(manifest))

				// Write a layer file
				layerContent := "test layer content"
				header = &tar.Header{
					Name: "layer1.tar",
					Size: int64(len(layerContent)),
					Mode: 0600,
				}
				tw.WriteHeader(header)
				tw.Write([]byte(layerContent))

				tw.Close()
				pw.Close()
			}()
			return pr, nil
		},
	}

	err := analyzeImageFilesystem(mockClient, "test-image")
	if err != nil {
		t.Errorf("analyzeImageFilesystem failed: %v", err)
	}
}

func TestPrintResults(t *testing.T) {
	// Test with verbose mode
	*verbose = true
	testLayers := []dockerHist{
		{
			CreatedBy:  "ADD file:123 /app",
			Layers:     []string{"layer1/file1", "layer1/file2"},
			EmptyLayer: false,
		},
	}
	printResults(testLayers)

	// Test with non-verbose mode
	*verbose = false
	printResults(testLayers)
}
