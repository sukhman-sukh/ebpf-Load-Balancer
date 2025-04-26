## Building and Running the Load Balancer

To get started, make sure you compile `libbpf`, which is a prerequisite for this project:

```bash
git submodule update --init --remote --recursive
cd external/libbpf
OBJDIR=build DESTDIR=install-dir make -C src install
```

Once that's complete, proceed to compile both the eBPF loader and the load balancer:

```bash
make all
```

---

## Creating the Test Environment


---

## How to  Deploy the eBPF Program


---

##  Results

