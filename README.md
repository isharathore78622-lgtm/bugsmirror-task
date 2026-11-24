# Threat Alert API

A small in-memory server (Go, standard library only) where the SDK reports threats
and company users view and resolve them.

## How to run

```
cd Backend_YourName
go run .
```

Server starts on port 8080 (or the `PORT` env variable if set).

Run tests:

```
go test -race ./...
```

## Project structure

- `go.mod` - module file, `go 1.22`, no `require` lines
- `main.go` - reads PORT and starts the server
- `models.go` - structs for User, App, Alert (json field names from the paper)
- `store.go` - the in-memory data + one mutex, all the logic for creating/finding/resolving
- `handlers.go` - the HTTP handlers, auth checks, input validation, routes
- `main_test.go` - the 3 required tests
- `.gitignore` - ignores built binaries

## What works and what does not

Works: all 7 routes, 401/403/400/404/409 in the order from R5, company separation,
repeat alerts, random tokens and keys, safe for concurrent requests. I ran the 22
self-check steps and they gave the expected results.

Not done: all the bonus parts (summary, paging, JSON file saving, Dockerfile,
graceful shutdown). Data is lost when the server restarts.

## How AI helped
- Tools I used: <WRITE THE TRUTH HERE>
- Two prompts I used (paste them as you typed them): <WRITE THE TRUTH HERE>
- One thing the AI got wrong, and how I found and fixed it: <WRITE THE TRUTH HERE>
- One part I wrote or changed myself without AI: <WRITE THE TRUTH HERE>

## Questions
1. Two identical alerts arrive at the same moment. Point to the lines in your code that make
sure only one alert is created.

   In `store.go`, `ReportAlert` takes the lock at line 126 (`s.mu.Lock()`) and releases it
   when the function returns (`defer`). Inside the lock it first searches for an open alert
   (the loop at line 133) and increments `Count` (line 136), or else creates a new one.
   Because the search and the create happen under the same lock, the second request has
   to wait and then finds the alert the first one made.

2. Why does a user from another company get 404 and not 403?

   403 would tell them "this alert exists but you can't touch it", which leaks that the id
   is real. With 404 an alert from another company looks exactly like an alert that never
   existed. In `store.go` (lines 191 and 204) the lookup treats a wrong company the same as a missing id.
