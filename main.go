// By Pegleg <pegleg@linux.com>
package main

import (
	"bufio"
	"context"
	"flag"
	"io"
	"os"
	"regexp"
	"strings"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/fatih/color"
	"archive/tar"
	"io/ioutil"
	"encoding/json"
	"errors"
	_ "net/http/pprof"
	"github.com/buger/jsonparser"
	"path/filepath"
	"net/url"
	"fmt"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/term"
)

const FilePerms = 0700

var filelist = flag.String("f", "", "File containing images to analyze seperated by line")
var verbose = flag.Bool("v", false, "Print all details about the image")
var filter = flag.Bool("filter", true, "Filters filenames that create noise such as" +
	" node_modules. Check ignore.go file for more details")
var extractLayers = flag.Bool("x", false, "Save layers to current directory")
var specificVersion = flag.String("sV", "", "Set the docker client ID to a specific version -sV=1.36")
var re *regexp.Regexp

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type ProgressDetail struct {
	Current int `json:"current"`
	Total int      `json:"total"`
}

type Status struct {
	Status string   `json:"status"`
	ID string   `json:"id"`
	ProgressDetail ProgressDetail `json:"progressDetail"`
}


type dockerHist struct {
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer"`
	LayerID    string
	Layers     []string
}

func printEnvironmentVariables(info types.ImageInspect) {
	if len(info.Config.Env) > 0 {
		color.White("Environment Variables")
		for _, ele := range info.Config.Env {
			color.Yellow("|%s", ele)
		}
		color.White("\n")
	}
}

func printPorts(info types.ImageInspect) {
	if len(info.Config.ExposedPorts) > 0 {
		color.White("Open Ports")
		for i := range info.Config.ExposedPorts {
			color.Green("|%s", i.Port())
		}
		color.White("\n")
	}
}

func printUserInfo(info types.ImageInspect) {
	color.White("Image user")
	if len(info.Config.User) == 0 {
		color.Red("|%s", "User is root")
	} else {
		color.Blue("|Image is running as User: %s", info.Config.User)
	}
	color.White("\n")
}


func analyze(cli *client.Client, imageID string) {
	info, _, err := cli.ImageInspectWithRaw(context.Background(), imageID)
	if err != nil {
		out, err := cli.ImagePull(context.Background(), imageID, types.ImagePullOptions{})
		if err != nil {
			color.Red(err.Error())
			color.Yellow("Use the -sV flag to change your client version. ./WhaleTail -sV=1.36 %s", imageID)
			return
		}
		defer out.Close()
		fd, isTerminal := term.GetFdInfo(os.Stdout)
		if err := jsonmessage.DisplayJSONMessagesStream(out, os.Stdout, fd, isTerminal, nil); err != nil {
			fmt.Println(err)
		}
		if err != nil {
			color.Red(err.Error())
			return
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
	err = analyzeImageFilesystem(cli, imageID)
	if err != nil {
		color.Red("%s", err)
	}

}

func analyzeSingleImage(cli *client.Client, imageID string) {
	analyze(cli, imageID)
}

func analyzeMultipleImages(cli *client.Client) {
	f, _ := os.Open(*filelist)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var imageIDs []string
	for scanner.Scan() {
		imageIDs = append(imageIDs, scanner.Text())
	}
	f.Close()
	for _, imageID := range imageIDs{
		analyzeSingleImage(cli, imageID)
	}
}

func extractImageLayers(cli *client.Client, imageID string, history []dockerHist) error{
	var startAt = 1
	if *verbose {
		startAt = 0
	}
	outputDir := filepath.Join(".", url.QueryEscape(imageID))
	os.MkdirAll(outputDir, FilePerms)
	f, err := os.Create(filepath.Join(outputDir, "mapping.txt"))
	if err != nil{
		return err
	}
	var layersToExtract = make(map[string]int)


	for i := startAt; i < len(history); i++ { //Skip the first layer as it clutters it
		if strings.Contains(history[i].CreatedBy, "ADD") || strings.Contains(history[i].CreatedBy, "COPY") {
			layersToExtract[history[i].LayerID] = 1
			layerID := strings.Split(history[i].LayerID, "/")[0]
			f.WriteString(fmt.Sprintf("%s:%s\n", layerID, history[i].CreatedBy))
		}
	}
	f.Close()
	imageStream, err := cli.ImageSave(context.Background(), []string{imageID})
	defer imageStream.Close()
	if err != nil {
		return err
	}
	tr := tar.NewReader(imageStream)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if _, ok := layersToExtract[hdr.Name]; ok{
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
					ioutil.WriteFile(filepath.Join(outputDir, layerID, name), data, FilePerms)
				case tar.TypeSymlink:
					/*
					Skipping Symlinks as there can be dangerous behavior here
					dest := filepath.Join(outputDir, layerID, name)
					source := hdrr.Linkname
					if _, err := os.Stat(dest); !os.IsNotExist(err) {
						color.Red("Refusing to overwrite existing file: %s", dest)
					}else {
						os.Symlink(source, dest)
					}
					*/
				}
			}

		}
	}
	imageStream.Close()
	return nil

}

func analyzeImageFilesystem(cli *client.Client, imageID string) (error) {
	imageStream, err := cli.ImageSave(context.Background(), []string{imageID})
	if err != nil {
		return err
	}
	tr := tar.NewReader(imageStream)
	var configs []Manifest
	var hist []dockerHist
	var layers = make(map[string][]string)
	color.White("Potential secrets:")
	for {
		imageFile, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if strings.Contains(imageFile.Name, ".json") && imageFile.Name != "manifest.json" {
			jsonBytes, _ := ioutil.ReadAll(tr)
			h, _, _, _ := jsonparser.Get(jsonBytes, "history")
			err = json.Unmarshal(h, &hist)
			if err != nil {
				return errors.New("unable to parse history from json file ")
			}

		}
		if imageFile.Name == "manifest.json" { //This file contains the sorted order of layers by the commands executed
			byteValue, _ := ioutil.ReadAll(tr)
			err = json.Unmarshal(byteValue, &configs)
			if err != nil {
				return errors.New("unable to parse manifest.json")
			}
		}
		if strings.Contains(imageFile.Name, "layer.tar") {
			ttr := tar.NewReader(tr)
			layers[imageFile.Name] = make([]string, 0)
			for {
				tarLayerFile, err := ttr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					color.Red("%s", err)
				}
				layers[imageFile.Name] = append(layers[imageFile.Name], tarLayerFile.Name)
				match := re.Find([]byte(tarLayerFile.Name))
				if match == nil {
					scanFilename(tarLayerFile.Name, imageFile.Name)
				}



			}
		}
	}
	layerIndex := 0
	result := hist[:0]
	for _, i := range hist {
		if !i.EmptyLayer {
			i.LayerID = configs[0].Layers[layerIndex]
			i.Layers = layers[i.LayerID]
			layerIndex++
			result = append(result, i)
		} else {
			result = append(result, i)
		}
	}
	if layerIndex != len(configs[0].Layers) {
		return errors.New("layers should always be 1:1 with commands")
	}
	imageStream.Close()
	printResults(result)
	if *extractLayers {
		err = extractImageLayers(cli, imageID, result)
		if err != nil{
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
	s = strings.Replace(s, "&&", " \\\n&&", -1)
	s = strings.Replace(s, "/bin/sh -c ", "", -1)
	s = strings.Replace(s, "#(nop) ", "", -1)
	return s
}

func main() {
	var cli *client.Client
	var err error
	flag.Parse()
	re = regexp.MustCompile(strings.Join(InternalWordlist, "|"))
	compileSecretPatterns()
	if len(*specificVersion) > 0 {
		cli, err = client.NewClientWithOpts(client.WithVersion(*specificVersion))
	} else{
		cli, err = client.NewClientWithOpts()
	}
	if err != nil {
		color.Red(err.Error())
		return
	}
	repo := flag.Arg(0)
	if len(*filelist) > 0{
		analyzeMultipleImages(cli)
	} else if len(repo) > 0 {
		imageID := repo
		analyzeSingleImage(cli, imageID)
	} else {
		color.Red("Please provide a repository image to analyze. ./WhaleTail nginx:latest")
		return
	}
	cli.Close()
}
