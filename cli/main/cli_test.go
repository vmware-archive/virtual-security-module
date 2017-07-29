package main

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"
)

type userData struct {
	Username       string
	PrivateKeyFile string
	PublicKeyFile  string
	Token          string
}

// Testuser data
var testUserData = userData{"user1", "test-user1-private.pem", "test-user1-public.pem", ""}

// Root user data
var rootData = userData{"root", "test-root-init-private.pem", "", ""}

// Return top level directory of project
func getProjectRootPath() string {
	var currentWorkingDirectory, _ = os.Getwd()
	var projectRootPath = path.Join(currentWorkingDirectory, "..", "..")
	return projectRootPath
}

// Get server executable path
func getServerExecutablePath() string {
	projectRootPath := getProjectRootPath()
	serverExecutableDir := path.Join(projectRootPath, "dist")
	serverExecutableFilename := "vsmd"
	serverExecutablePath := path.Join(serverExecutableDir, serverExecutableFilename)
	return serverExecutablePath
}

// Main function for test. Used here as an alternate for
// setup() and teardown() phase
func TestMain(m *testing.M) {
	serverExecutablePath := getServerExecutablePath()
	cmd := exec.Command(serverExecutablePath)
	cmd.Start()
	time.Sleep(time.Second * 3)
	v := m.Run()
	cmd.Process.Kill()
	os.Exit(v)
}

func getOutput(command string) (string, error) {
	projectRootPath := getProjectRootPath()
	cliExecutableName := "vsm-cli"
	cliExecutablePath := path.Join(projectRootPath, "dist", cliExecutableName)
	cmd := exec.Command(cliExecutablePath, strings.Split(command, " ")...)
	output, err := cmd.CombinedOutput()
	return bytes.NewBuffer(output).String(), err
}

// Test login using pre-created root account
func TestRootLogin(t *testing.T) {

	projectRootPath := getProjectRootPath()
	certFileName := "test-root-init-private.pem"
	certFilePath := path.Join(projectRootPath, "certs", certFileName)
	command := "login root" + " " + certFilePath
	output, _ := getOutput(command)

	check1 := strings.Contains(output, "Login successful")
	check2 := strings.Contains(output, "Token:")

	finalCheck := check1 && check2

	if finalCheck == false {
		t.Fail()
	} else {
		index := strings.Index(output, "Token:")
		rootData.Token = strings.Trim(output[index+7:], "\n")
	}
}

// Test user creation
func TestUserCreate(t *testing.T) {

	command := "--token " + rootData.Token + " users create " + testUserData.Username + " " + testUserData.PublicKeyFile
	output, _ := getOutput(command)

	check1 := strings.Contains(output, "User created successfully")
	check2 := strings.Contains(output, "Id: "+testUserData.Username)

	finalCheck := check1 && check2

	if finalCheck == false {
		t.Fail()
	}
}

// Test user data retrieval
func TestUserGet(t *testing.T) {
	command := "--token " + rootData.Token + " users get " + testUserData.Username
	output, _ := getOutput(command)

	check1 := strings.Contains(output, "\"username\": \""+testUserData.Username+"\"")
	check2 := strings.Contains(output, "\"credentials\"")

	finalCheck := check1 && check2

	if finalCheck == false {
		t.Fail()
	}
}

// Test user deletion
func TestUserDelete(t *testing.T) {
	command := "--token " + rootData.Token + " users delete " + testUserData.Username
	output, _ := getOutput(command)

	check1 := strings.Contains(output, "User deleted successfully")

	if check1 == false {
		t.Fail()
	}
}
