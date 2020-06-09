# subdscan
Subdomain fast search tool

## Usage
```
# params
-d string
      Set domain scan like '-d ya.ru'
-t int
      Set parallelism like '-t 50' (default 10)
-ui int
      Enable user interface on port '-ui 8080'
-w string
      Set subdomains dictionary file like '-w wordlist.txt' (default "wordlist.txt")
```

### run console
```bash
./subdscan -d somesite.ru
```

### Run UI with Docker
#### build
```bash
docker build -t subscan:latest .
```

#### run
```bash
docker run --rm -p 80:80 -e SERVER_HOST=0.0.0.0 subscan:latest
```

![](example.png)

### run web ui
```bash
./subdscan -ui 1234
```

![](example-webui.png)


# Wordlist file
You can find them in the internet, for example https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
