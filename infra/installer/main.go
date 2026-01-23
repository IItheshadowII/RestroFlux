package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "time"
)

func run(name string, args ...string) error {
    cmd := exec.Command(name, args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
}

func copyFile(src, dst string) error {
    in, err := os.Open(src)
    if err != nil { return err }
    defer in.Close()
    out, err := os.Create(dst)
    if err != nil { return err }
    defer out.Close()
    _, err = io.Copy(out, in)
    if err != nil { return err }
    return out.Sync()
}

func fileExists(p string) bool {
    _, err := os.Stat(p)
    return err == nil
}

func findRepoRoot() (string, error) {
    // assume executable is in infra/installer
    exe, err := os.Executable()
    if err != nil { return "", err }
    dir := filepath.Dir(exe)
    // in dev, running `go run`, cwd is project; try relative
    repo := filepath.Clean(filepath.Join(dir, "..", ".."))
    if fileExists(filepath.Join(repo, "package.json")) || fileExists(filepath.Join(repo, "server.js")) {
        return repo, nil
    }
    // fallback to working dir
    cwd, _ := os.Getwd()
    return cwd, nil
}

func waitForPostgres(container string, timeout time.Duration) error {
    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        err := run("docker", "exec", container, "pg_isready", "-U", "gastroflow")
        if err == nil { return nil }
        time.Sleep(2 * time.Second)
    }
    return fmt.Errorf("timeout waiting for postgres")
}

func main() {
    license := flag.String("license", "", "License key to write into .env.onprem")
    instance := flag.String("instance", "local-instance", "Instance ID")
    flag.Parse()

    // check docker
    if err := run("docker", "--version"); err != nil {
        fmt.Println("Docker not found. Please install Docker Desktop and retry.")
        os.Exit(1)
    }

    repo, err := findRepoRoot()
    if err != nil {
        fmt.Println("Cannot determine repo root:", err)
        os.Exit(1)
    }

    fmt.Println("Repo root:", repo)

    infraDir := filepath.Join(repo, "infra")
    envExample := filepath.Join(infraDir, ".env.onprem.example")
    envFile := filepath.Join(infraDir, ".env.onprem")

    if !fileExists(envFile) {
        if !fileExists(envExample) {
            fmt.Println("Missing infra/.env.onprem.example")
            os.Exit(1)
        }
        if err := copyFile(envExample, envFile); err != nil {
            fmt.Println("failed to copy env example:", err)
            os.Exit(1)
        }
        fmt.Println("Created infra/.env.onprem from example. Edit if needed.")
    }

    if *license != "" {
        // naive replacement: append or replace line
        f, err := os.OpenFile(envFile, os.O_RDWR, 0644)
        if err == nil {
            scanner := bufio.NewScanner(f)
            var lines []string
            for scanner.Scan() { lines = append(lines, scanner.Text()) }
            replaced := false
            for i, l := range lines {
                if len(l) >= 12 && l[:12] == "VITE_LICENSE_" { lines[i] = "VITE_LICENSE_KEY=" + *license; replaced = true }
                if len(l) >= 14 && l[:14] == "VITE_INSTANCE_ID" { lines[i] = "VITE_INSTANCE_ID=" + *instance }
            }
            if !replaced { lines = append(lines, "VITE_LICENSE_KEY="+*license) }
            // write back
            f.Close()
            os.WriteFile(envFile, []byte(fmt.Sprintln(stringsJoin(lines, "\n"))), 0644)
            fmt.Println("Wrote license to infra/.env.onprem")
        }
    }

    // ensure data dirs
    _ = os.MkdirAll(filepath.Join(infraDir, "data", "uploads"), 0755)
    _ = os.MkdirAll(filepath.Join(infraDir, "data", "pgdata"), 0755)
    _ = os.MkdirAll(filepath.Join(infraDir, "data", "miniodata"), 0755)

    // run docker compose
    compose1 := filepath.Join(repo, "docker-compose.yml")
    compose2 := filepath.Join(infraDir, "docker-compose.onprem.yml")
    fmt.Println("Running docker compose up -d --build")
    if err := run("docker", "compose", "-f", compose1, "-f", compose2, "up", "-d", "--build"); err != nil {
        fmt.Println("docker compose failed:", err)
        os.Exit(1)
    }

    // find postgres container
    out, _ := exec.Command("docker", "ps", "-qf", "ancestor=postgres:15").Output()
    container := string(out)
    if container == "" {
        out2, _ := exec.Command("docker", "ps", "-qf", "ancestor=postgres:15-alpine").Output()
        container = string(out2)
    }
    container = trimSpaces(container)
    if container == "" {
        fmt.Println("Could not find postgres container; check docker ps")
        os.Exit(1)
    }

    fmt.Println("Waiting for Postgres to be ready...")
    if err := waitForPostgres(container, 2*time.Minute); err != nil {
        fmt.Println("Postgres not ready:", err)
    } else {
        // apply migrations if exist
        initSql := filepath.Join(repo, "db", "init.sql")
        if fileExists(initSql) {
            fmt.Println("Applying db/init.sql")
            _ = run("docker", "cp", initSql, container+":/tmp/init.sql")
            _ = run("docker", "exec", container, "psql", "-U", "gastroflow", "-d", "gastroflow", "-f", "/tmp/init.sql")
        }
    }

    fmt.Println("Installation finished. Use docker compose logs -f app to inspect logs.")
}

// helper small functions to avoid adding extra imports like strings
func stringsJoin(parts []string, sep string) string {
    if len(parts) == 0 { return "" }
    out := parts[0]
    for i := 1; i < len(parts); i++ { out += sep + parts[i] }
    return out
}

func trimSpaces(s string) string {
    b := []byte(s)
    // remove whitespace and newlines
    var res []byte
    for _, c := range b {
        if c != '\n' && c != '\r' && c != ' ' && c != '\t' { res = append(res, c) }
    }
    return string(res)
}
