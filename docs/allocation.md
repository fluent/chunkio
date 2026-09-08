# Chunk allocation and growth

`cio_chunk_open(..., size, ...)` treats `size` as initial capacity, not a
content length or maximum chunk size. New or empty filesystem chunks reserve
`max(size, CIO_FILE_HEADER_MIN)`, rounded to a page. This capacity includes the
file header and subsequent metadata. Memory chunks reserve `size` content bytes;
their metadata is separate.

Nonempty files keep their existing size, including when reopened read-only or
loaded as backlog. A deferred open retains its hint until the first successful
mapping, but uses an existing file's size if that file appears before mapping.
If reserving or mapping a valid filesystem hint fails, creation retries with
one page. Unrepresentable hints on new files return an error.

## Adaptive growth

Adaptive growth is enabled by default, including when callers assign their own
`options.flags` or create a context with `cio_create(NULL)`. To explicitly retain
the previous fixed growth policy:

```c
struct cio_options options;

cio_options_init(&options);
options.flags |= CIO_FIXED_GROWTH;
```

Growth is computed independently for each chunk, only when an append exceeds
its capacity. The increment is:

```
max(configured_realloc_step, min(current_capacity / 2, 256 KiB))
```

The allocation covers the entire append in one resize, rounding up by that
increment, then to a page for filesystem storage. Explicit reallocation hints
larger than 256 KiB retain their configured size. There is no stream-level
learning or interpretation of metadata, tags, routes, or record contents.
Trimming reduces the capacity used by the next growth calculation.

If optional headroom cannot be allocated, adaptive writes retry with just the
required capacity (page-rounded for filesystem storage). Failed appends leave
content length and checksum state unchanged. Unix mapping failures retain the
old mapping and attempt to undo the disk reservation. If undoing that reservation
also fails, the larger file size remains visible in accounting and projection.

## Consumer accounting

`cio_chunk_get_projected_size(chunk, append_bytes, &capacity)` returns an upper
bound on capacity after an append. The chunk must be up. Filesystem results
include the header, metadata, and any outstanding disk reservation; memory
results describe the content buffer. An allocation fallback can use less space.
Errors leave the output argument unchanged. Serialize projection and append
with other mutations, including metadata changes and trimming.

The sibling Fluent Bit implementation in `src/flb_input_chunk.c` currently
predicts fixed growth from ChunkIO's leading allocation fields. Those fields
retain their offsets, and fixed growth retains that calculation. Fluent Bit
must adopt the projection API when updating to this version, or explicitly set
`CIO_FIXED_GROWTH` until that integration is complete. Otherwise its output
storage limits could underestimate the new default growth. For a new chunk, budget
the entire projected size; for an already accounted chunk, budget its positive
increase over the previously accounted size.

**Honoring the opening hint has a cost for tiny chunks.** Fluent Bit currently
requests 256 KiB: a one-page chunk can therefore reserve 64 times as much space
on a system with 4 KiB pages. Many low-volume tags can increase disk usage and
creation cost even with adaptive growth disabled. Callers should select smaller
hints for that workload. A hint of zero retains minimum initial allocation.
This change does not alter the on-disk format.

## Verification

`tests/allocation.c` covers both backends and both growth policies, checksums
on/off, full sync, arbitrary reallocation steps, large single appends, maximum
metadata, overflow boundaries, zero-byte truncation, transaction rollback,
read-only and corrupt-file reopen, backlog loading, deferred creation, trim and
regrowth, and independence between hot and cold chunks. Fixed-growth expectations
use the consumer's existing increment calculation; projected capacity is checked
against actual allocation after each successful write.

Linux linker wrappers inject reservation, mmap/mremap, stat, and realloc errors.
Tests check retry, content preservation, counters, descriptor cleanup, minimal
allocation fallback, failed writes at offsets, and failure to undo a reservation.
These failure-injection cases are not compiled on Windows or macOS.

The tests exposed two surrounding bugs, fixed alongside allocation: failed
offset writes retained a shortened length, and checksum-disabled transaction
rollback did not persist the restored length. The PR also persists the logical
length when truncating through zero-byte writes and when syncing a rollback.
These changes are tested directly against upstream master; the separate local
checksum-recovery commits are not included.

All seven suites passed on Linux x86-64 with GCC, strict Valgrind, and Clang
AddressSanitizer/UndefinedBehaviorSanitizer. The legacy Acutest callback function
type check is excluded (`-fno-sanitize=function`); address, leak, and other UB
checks remain enabled. Tests use `--exec=never` for sanitizer/Valgrind execution.
The portable Unix mmap replacement path was also forced in an isolated Linux
source copy and passed all seven suites. This does not establish Windows/macOS
runtime compatibility. A full Fluent Bit pipeline was not run against this patch.

## Reproducible benchmark

On Linux with GCC or Clang, build a release library and the standalone harness
without `-DNDEBUG` (the harness checks every operation):

```sh
cmake -S . -B /tmp/cio-release -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/cio-release -j8
cc -O3 -Iinclude -Ideps -Ideps/monkey/include -I/tmp/cio-release/include \
  tools/cio_bench_allocation.c /tmp/cio-release/src/libchunkio-static.a \
  /tmp/cio-release/deps/crc32/libcio-crc32.a \
  -Wl,--wrap=cio_file_native_remap -Wl,--wrap=realloc \
  -o /tmp/cio-bench-allocation
/tmp/cio-bench-allocation fs 100 2048000 1024 262144 0 1
/tmp/cio-bench-allocation fs 100 2048000 1024 262144 1 1
```

Arguments are backend, chunk count, bytes per chunk, append batch, opening hint,
adaptive flag, and checksum flag. The harness verifies payload and metadata
after down/up. It can also link against the original library for comparison.

Earlier local measurements before moving the patch to upstream master:
Linux x86-64, ext4/NVMe, GCC 13.3, seven runs per case, medians.
The original baseline was local commit `fa2f463`; these are not measurements of
the final PR commit. The growth policies and allocation counts are unchanged.
Each filesystem chunk has 64 bytes of metadata. Timings include creation,
writing, normal sync, verification after reload, and deletion; full sync is off.

| Workload | Original | Honor hint, fixed growth | Honor hint, adaptive |
| --- | ---: | ---: | ---: |
| 100 FS chunks, 2,048,000 bytes, 1 KiB appends, checksum off | 360.9 ms | 319.3 ms | 119.6 ms |
| Same, checksum on | 500.0 ms | 462.9 ms | 255.9 ms |
| Remaps per chunk in these workloads | 63 | 55 | 8 |
| Final reserved bytes per chunk | 2,068,480 | 2,064,384 | 2,162,688 |
| 500 FS chunks, one 1 KiB append each, checksum off | 22.5 ms | 43.4 ms | 42.9 ms |

A longer memory-backend check (2,000 chunks, 2,048,000 bytes each, 1 KiB
appends, fixed growth, nine runs) measured 139.3 ms original and 140.4 ms changed;
run ranges overlapped. These measurements do not imply an equivalent Fluent Bit
throughput gain or guarantee identical performance across filesystems/workloads.
