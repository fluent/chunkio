# Chunk I/O

Chunk I/O is a simple library that helps to manage chunks of data into the file system, providing a simple  interface.

## Internals

the library fill the requirement of to have a _root path_ as a main storage point where different _streams_ contains data files called chunks:

```
root_path/
root_path/stream_1/
root_path/stream_1/chunk1
root_path/stream_1/chunk2
root_path/stream_1/chunkN
root_path/stream_N
```

Creating a file system structure like the proposed one requires several checks and usage of I/O interfaces, Chunk I/O aims to abstract the internals of I/O interfaces providing helpers that behind the scenes relies on mmap(2), msync(2), munmap(2) and ftruncate(2).

In the other side if the library root_path points to an existent tree with stream and chunks, those are loaded in memory (on demand) so it can be used by the caller.

### Concepts

It's up to the caller program how to define the names, basically it needs to set streams and associate chunks to it:

| concept   | description                                                  |
| --------- | ------------------------------------------------------------ |
| root_path | storage area, file system directory that exists or can be created |
| stream    | directory or parent group of chunks of files. The stream name is customizable, it can be anything allowed by the file system. |
| chunk     | regular file that contains the data.                         |

## cio - client tool

This repository comes with a tool for testing purposes called _cio_, a quick start for testing could be to stream a file over STDIN and flush it under a specific stream and chunk name, e.g:

```bash
$ cat somefile | tools/cio -i -s stdin -f data -v
```

the command above specify to gather data from the standard input (_-i_), use a stream called _stdin_ (_-s stdin_) and store the data into the chunk called _data_ (_-f data_)  and enabling some verbose messages (_-v_)

```bash
[chunkio] created root path /home/edsiper/.cio             => src/chunkio.c:48
[chunkio] [cio scan] opening path /home/edsiper/.cio       => src/cio_scan.c:95
[chunkio] created stream path /home/edsiper/.cio/stdin     => src/cio_stream.c:62
[chunkio] [cio stream] new stream registered: stdin        => src/cio_stream.c:105
[chunkio] stdin:data mapped OK                             => src/cio_file.c:137
[chunkio] [cio file] file synced at: stdin/data            => src/cio_file.c:247
[  cli  ] stdin total bytes => 153 (153b)                  => tools/cio.c:244

```

## File Layout

Each file created by the library have the following layout:

```
+--------------+----------------+
|     0xC1     |     0x00       +--> Header 2 bytes
+--------------+----------------+
|           20 BYTES            +--> SHA1(Content)
+-------------------------------+
|            Content            |
|  +-------------------------+  |
|  |         2 BYTES         +-----> Metadata Length
|  +-------------------------+  |
|  +-------------------------+  |
|  |                         |  |
|  |        Metadata         +-----> Optional Metadata (up to 65535 bytes)
|  |                         |  |
|  +-------------------------+  |
|  +-------------------------+  |
|  |                         |  |
|  |       Content Data      +-----> User Data
|  |                         |  |
|  +-------------------------+  |
+-------------------------------+
```

## TODO

- [ ] Document C API: dev is still in progress, so constant changes are expected
- [ ] Restricted memory mapping: load in memory up to a limit, not all the content of a root_path
- [ ] Export metrics

## License

Chunk I/O is under the terms of [Apache License v2.0](LICENSE)
