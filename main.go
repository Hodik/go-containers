package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

type TokenResp struct {
	Token string `json:"token"`
}

type Manifest struct {
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			Os           string `json:"os"`
		} `json:"platform"`
	} `json:"manifests"`
}

type TagResp struct {
	Config struct {
		Digest string `json:"digest"`
	}
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

type Config struct {
	Env        []string `json:"Env"`
	Cmd        []string `json:"Cmd"`
	WorkingDir string   `json:"WorkingDir"`
}

type ConfigContainer struct {
	Config Config `json:"Config"`
}

const registry = "https://registry-1.docker.io/v2"

func main() {
	log.Println(os.Args)
	switch os.Args[1] {
	case "run":
		run()
	case "child":
		child()
	case "pull":
		pull(os.Args[2])
	default:
		panic("bad command")
	}
}

func child() {
	log.Printf("Running: %v as %d\n", os.Args[2:], os.Getpid())
	image := os.Args[2]

	image_name, filename := pull(image)
	log.Println("Pulling complete: ", image_name, filename)

	imageConfig, err := readImageConfig(filename)

	if err != nil {
		log.Fatalln("Error reading image config: ", err.Error())
	}

	syscall.Sethostname([]byte(image_name))
	syscall.Chroot(filename)
	syscall.Chdir("/")
	syscall.Mount("proc", "proc", "proc", 0, "")
	cmd, err := applyImageConfig(imageConfig)
	if err != nil {
		log.Fatalln("Error applying image config: ", err.Error())
	}

	config := syscall.ProcAttr{
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Env:   os.Environ(),
	}

	var process_args []string
	var process string

	if len(os.Args) > 3 {
		process = os.Args[3]

		if len(os.Args) >= 4 {
			process_args = os.Args[4:]
		}
	} else if cmd != nil {
		process = cmd[0]

		if len(cmd) > 1 {
			process_args = cmd[1:]
		}
	} else {
		log.Fatalln("No cmd provided, no cmd in set in image")
	}
	childPid, _, err := syscall.StartProcess(process, process_args, &config)
	if err != nil {
		log.Fatalln("Error executing program", process, process_args, err.Error())
	}
	log.Println("Started", process, process_args, " process with pid", childPid)
	syscall.Wait4(int(childPid), nil, 0, nil)
	syscall.Unmount("proc", 0)

	log.Println("Finishing child container process")
}

func readImageConfig(imageDir string) (*Config, error) {
	file, err := os.Open(fmt.Sprintf("%s/config.json", imageDir))

	if err != nil {
		return nil, err
	}

	var configContainer ConfigContainer
	if err := json.NewDecoder(file).Decode(&configContainer); err != nil {
		return nil, err
	}

	return &configContainer.Config, nil
}

func applyImageConfig(c *Config) ([]string, error) {
	for _, envVar := range c.Env {
		parsedVar := strings.Split(envVar, "=")

		log.Println("Applying env", parsedVar)
		if err := os.Setenv(parsedVar[0], parsedVar[1]); err != nil {
			return nil, err
		}
	}
	if err := syscall.Chdir(c.WorkingDir); err != nil {
		return nil, err
	}
	return c.Cmd, nil
}

func run() {
	log.Printf("Running: %v as %d\n", os.Args[2:], os.Getpid())

	config := syscall.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Cloneflags:   syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
			Unshareflags: syscall.CLONE_NEWNS,
		},
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
	}
	childPid, _, err := syscall.StartProcess("/proc/self/exe", append([]string{os.Args[0], "child"}, os.Args[2:]...), &config)
	if err != nil {
		log.Fatalln("Failed to start a child process", err)
	}
	syscall.Wait4(int(childPid), nil, 0, nil)
}

func pull(_image string) (image_name string, filename string) {
	image := strings.Split(_image, ":")

	if len(image) != 2 {
		log.Fatalln("provide image:tag")
	}
	image_splitted := strings.Split(image[0], "/")
	if len(image_splitted) > 1 {
		image_name = image_splitted[1]
	} else {
		image_name = image_splitted[0]
	}
	filename = fmt.Sprintf("/tmp/%s-fs", image_name)
	if _, err := os.Open(filename); err == nil {
		log.Println(image_name, "already loaded")
		return image_name, filename
	}
	pullImage(image[0], image[1], filename)
	return image_name, filename
}

func pullImage(imageName string, tag string, outputDir string) {
	log.Printf("Pulling image: %v\n", imageName)
	token, err := fetchToken(imageName)

	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Println("fetched token", token)
	tagResp, err := fetchTag(imageName, tag, token)

	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		log.Fatalf("failed to create output directory: %s", err.Error())
	}

	if err != nil {
		log.Fatalln(err.Error())
	}

	c, err := fetchConfig(imageName, tagResp.Config.Digest, token)

	if err != nil {
		log.Fatalln("Error pulling image config:", err.Error())
	}

	if err := extractConfig(c, outputDir); err != nil {
		log.Fatalln("Error extracting config into image fs", err.Error())
	}

	for _, layer := range tagResp.Layers {
		log.Println("Downloading layer: ", layer.Digest)
		if err := downloadAndExtractLayer(imageName, layer.Digest, token, outputDir); err != nil {
			log.Fatalf("failed to process layer %s: %s", layer.Digest, err.Error())
		}
	}

}

func extractConfig(c []byte, outputDir string) error {
	file, err := os.Create(fmt.Sprintf("%s/config.json", outputDir))

	if err != nil {
		return err
	}

	if _, err := file.Write(c); err != nil {
		return err
	}

	return nil
}

func fetchConfig(image, digest, token string) ([]byte, error) {
	// Construct the URL to fetch the layer blob.
	url := fmt.Sprintf("%s/%s/blobs/%s", registry, image, digest)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// Make the HTTP request to download the layer.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download layer: %w", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func fetchToken(imageName string) (string, error) {

	url := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", imageName)
	resp, err := http.Get(url)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	var tokenResp TokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", nil
	}

	return tokenResp.Token, nil
}

func fetchTag(image, tag, token string) (*TagResp, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", registry, image, tag)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch tag " + resp.Status)
	}

	var m Manifest

	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}

	log.Println(m)

	var digest string

	for i := 0; i < len(m.Manifests); i++ {
		if m.Manifests[i].Platform.Architecture == "arm64" && m.Manifests[i].Platform.Os == "linux" {
			digest = m.Manifests[i].Digest
			break
		}
	}

	if digest == "" {
		return nil, errors.New("Digest for system not found")
	}

	log.Println("digest", digest)

	url2 := fmt.Sprintf("%s/%s/manifests/%s", registry, image, digest)
	req2, _ := http.NewRequest("GET", url2, nil)
	req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req2.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp2, err := http.DefaultClient.Do(req2)

	if err != nil {
		return nil, err
	}

	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch tag " + resp2.Status)
	}

	// b, _ := io.ReadAll(resp.Body)
	// log.Println("resp: ", string(b))

	var tagResp TagResp

	if err := json.NewDecoder(resp2.Body).Decode(&tagResp); err != nil {
		return nil, err
	}

	return &tagResp, nil
}

func downloadAndExtractLayer(image, digest, token, outputDir string) error {
	// Construct the URL to fetch the layer blob.
	url := fmt.Sprintf("%s/%s/blobs/%s", registry, image, digest)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// Make the HTTP request to download the layer.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download layer: %w", err)
	}
	defer resp.Body.Close()

	// Check if the HTTP status code is OK.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download layer: %s", resp.Status)
	}

	// Create a temporary file to store the downloaded layer.
	tmpFile, err := os.Create("/tmp/layer.tar")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer tmpFile.Close()

	// Write the response body (layer blob) to the temp file.
	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write layer blob to file: %w", err)
	}

	// Now, use `tar` command to extract the layer into the output directory.
	// Use `tar xf` to extract the tarball.
	cmd := exec.Command("/usr/bin/tar", "xf", tmpFile.Name(), "-C", outputDir)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to extract layer: %w", err)
	}

	// Clean up the temporary file after extraction.
	err = os.Remove(tmpFile.Name())
	if err != nil {
		log.Printf("Warning: failed to remove temporary tar file: %v", err)
	}

	log.Println("Layer extracted successfully.")
	return nil
}
