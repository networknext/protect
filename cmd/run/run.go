package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"runtime"
)

var cmd *exec.Cmd

func bash(command string) {

	cmd = exec.Command("bash", "-c", command)
	if cmd == nil {
		fmt.Printf("error: could not run bash!\n")
		os.Exit(1)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH=.")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		if cmd.Process != nil {
			fmt.Printf("\n\n")
			if err := cmd.Process.Signal(sig); err != nil {
				fmt.Printf("error trying to signal child process: %v\n", err)
			}
			cmd.Wait()
		}
		os.Exit(1)
	}()

	if err := cmd.Run(); err != nil {
		fmt.Printf("error: failed to run command: %v\n", err)
		os.Exit(1)
	}

	cmd.Wait()
}

func bash_ignore_result(command string) {

	cmd = exec.Command("bash", "-c", command)
	if cmd == nil {
		fmt.Printf("error: could not run bash!\n")
		os.Exit(1)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout

	cmd.Run()

	cmd.Wait()
}

func bash_no_wait(command string) {

	cmd = exec.Command("bash", "-c", command)
	if cmd == nil {
		fmt.Printf("error: could not run bash!\n")
		os.Exit(1)
	}

	cmd.Run()
}

func main() {

	args := os.Args

	if len(args) < 2 || (len(args) == 2 && args[1] == "help") {
		help()
		return
	}

	command := args[1]

	if command == "client" {
		client()
	} else if command == "server" {
		server()
	} else if command == "test" {
		test()
	} else if command == "keygen" {
		keygen()
	} else if command == "proton" {
		proton()
	} else if command == "client-backend" {
		client_backend()
	} else {
		fmt.Printf("\nunknown command\n\n")
	}
}

func help() {
	fmt.Printf("\nsyntax:\n\n    run <action> [args]\n\n")
}

func client_backend() {
	if runtime.GOOS == "linux" {
		bash("cd dist && sudo CLIENT_BACKEND_PUBLIC_ADDRESS=45.250.253.243:40000 CLIENT_BACKEND_PRIVATE_KEY=otPzITpGBQbhk0F4u19zjobra/ez4F5YGDekxQI+HFw= ./client_backend")
	} else {
		bash("cd dist && CLIENT_BACKEND_PUBLIC_ADDRESS=45.250.253.243:40000 CLIENT_BACKEND_PRIVATE_KEY=otPzITpGBQbhk0F4u19zjobra/ez4F5YGDekxQI+HFw= ./client_backend")
	}
}

func client() {
	bash("./dist/client")
}

func server() {
	if runtime.GOOS == "linux" {
		bash("sudo ./dist/server")
	} else {
		bash("./dist/server")
	}
}

func test() {
	bash("./dist/test")
}

func keygen() {
	bash("./dist/keygen")
}

func proton() {
	bash("cd lib/proton && make")	
}
