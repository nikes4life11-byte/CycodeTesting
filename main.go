// WARNING: THIS PROGRAM IS INTENTIONALLY VULNERABLE.
// DO NOT USE IN PRODUCTION. FOR SECURITY SCANNER TESTING ONLY.

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	http.HandleFunc("/sqli", sqlInjectionHandler)
	http.HandleFunc("/xss", xssHandler)
	http.HandleFunc("/file", fileReadHandler)
	http.HandleFunc("/exec", commandInjectionHandler)

	log.Println("Starting intentionally vulnerable server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// =======================
// 1) SQL Injection (CWE-89)
// =======================
func sqlInjectionHandler(w http.ResponseWriter, r *http.Request) {
	// Example DSN: user:pass@tcp(127.0.0.1:3306)/testdb
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		http.Error(w, "Set TEST_DB_DSN env var for SQLi test", http.StatusInternalServerError)
		return
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		http.Error(w, "DB open error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Untrusted input from query string
	user := r.URL.Query().Get("user")
	if user == "" {
		http.Error(w, "Missing 'user' parameter", http.StatusBadRequest)
		return
	}

	// VULNERABLE: directly concatenating user input into SQL query
	query := "SELECT id, username FROM users WHERE username = '" + user + "'"

	log.Println("Executing query:", query)

	row := db.QueryRow(query)
	var id int
	var username string
	if err := row.Scan(&id, &username); err != nil {
		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "User found: id=%d username=%s\n", id, username)
}

// =======================
// 2) Reflected XSS (CWE-79)
// =======================
func xssHandler(w http.ResponseWriter, r *http.Request) {
	// Untrusted input from query string
	msg := r.URL.Query().Get("msg")

	// VULNERABLE: unescaped output directly in HTML
	// e.g. /xss?msg=<script>alert(1)</script>
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<html>
			<head><title>XSS Test</title></head>
			<body>
				<h1>XSS Test Page</h1>
				<p>You said: %s</p>
			</body>
		</html>
	`, msg)
}

// ===========================================
// 3) Directory Traversal / File Read (CWE-22)
// ===========================================
func fileReadHandler(w http.ResponseWriter, r *http.Request) {
	// Untrusted input from query string
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Missing 'name' parameter", http.StatusBadRequest)
		return
	}

	// VULNERABLE: naive concatenation allows ../ traversal
	// e.g. /file?name=../../../../etc/passwd
	baseDir := "./uploads/"
	fullPath := baseDir + name

	log.Println("Reading file:", fullPath)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "Error reading file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

// ====================================
// 4) Command Injection (CWE-78)
// ====================================
func commandInjectionHandler(w http.ResponseWriter, r *http.Request) {
	// Untrusted input from query string
	cmdStr := r.URL.Query().Get("cmd")
	if cmdStr == "" {
		http.Error(w, "Missing 'cmd' parameter", http.StatusBadRequest)
		return
	}

	// VULNERABLE: passes user input directly to shell
	// e.g. /exec?cmd=ls;id
	log.Println("Executing shell command:", cmdStr)
	out, err := exec.Command("sh", "-c", cmdStr).CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Command error: %v\nOutput:\n%s", err, string(out))
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(out)
}
