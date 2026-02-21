# getpara
Fetch all URL query parameters from a domain using historical and live sources.

Usage example: 
```
# fetch params for a single domain
getpara example.com

# fetch params with snapshot dates
getpara -dates example.com

# fetch params from multiple domains via stdin
cat domains.txt | getpara -dates

# exclude subdomains
getpara -no-subs example.com
```

Install:
```
# Install via Go
go install github.com/amineelg99/getpara@latest
```
