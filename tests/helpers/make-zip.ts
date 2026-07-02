/**
 * Minimal ZIP file writer for tests.
 *
 * Built by hand from Node's `node:zlib` (`crc32` + `deflateRawSync`) so the
 * test suite can construct a ZIP whose entry name is an arbitrary string —
 * including a path-traversal name like `../../etc/passwd` that cannot be
 * created as a real file on disk first and then zipped by a normal
 * zip-creation CLI/library (most refuse to write such an entry name).
 * Writing the ZIP central-directory bytes directly sidesteps that
 * restriction entirely. Never shells out to a `zip` binary or any other
 * subprocess.
 *
 * This is a deliberately tiny ZIP encoder: store-or-deflate entries, no
 * ZIP64, no encryption, no extra fields — exactly enough format support to
 * exercise `resolveInput`'s ZIP mode (benign extraction + the malicious
 * traversal-entry rejection case).
 */
import { writeFile } from "node:fs/promises";
import { crc32, deflateRawSync } from "node:zlib";

/** Map of ZIP entry name -> raw (uncompressed) file contents. */
export type ZipEntries = Record<string, string>;

const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const VERSION_NEEDED = 20; // 2.0 — deflate support
const VERSION_MADE_BY = 20;
const METHOD_DEFLATE = 8;

interface BuiltEntry {
  nameBuffer: Buffer;
  compressed: Buffer;
  crc: number;
  uncompressedSize: number;
  compressedSize: number;
  localHeaderOffset: number;
}

function buildEntry(name: string, contents: string, offset: number): BuiltEntry {
  const nameBuffer = Buffer.from(name, "utf8");
  const rawBuffer = Buffer.from(contents, "utf8");
  const compressed = deflateRawSync(rawBuffer);
  return {
    nameBuffer,
    compressed,
    crc: crc32(rawBuffer),
    uncompressedSize: rawBuffer.length,
    compressedSize: compressed.length,
    localHeaderOffset: offset,
  };
}

function writeLocalFileHeader(entry: BuiltEntry): Buffer {
  const header = Buffer.alloc(30);
  header.writeUInt32LE(LOCAL_FILE_HEADER_SIGNATURE, 0);
  header.writeUInt16LE(VERSION_NEEDED, 4);
  header.writeUInt16LE(0, 6); // general purpose bit flag
  header.writeUInt16LE(METHOD_DEFLATE, 8);
  header.writeUInt16LE(0, 10); // last mod file time
  header.writeUInt16LE(0, 12); // last mod file date
  header.writeUInt32LE(entry.crc, 14);
  header.writeUInt32LE(entry.compressedSize, 18);
  header.writeUInt32LE(entry.uncompressedSize, 22);
  header.writeUInt16LE(entry.nameBuffer.length, 26);
  header.writeUInt16LE(0, 28); // extra field length
  return Buffer.concat([header, entry.nameBuffer]);
}

function writeCentralDirectoryHeader(entry: BuiltEntry): Buffer {
  const header = Buffer.alloc(46);
  header.writeUInt32LE(CENTRAL_DIRECTORY_SIGNATURE, 0);
  header.writeUInt16LE(VERSION_MADE_BY, 4);
  header.writeUInt16LE(VERSION_NEEDED, 6);
  header.writeUInt16LE(0, 8); // general purpose bit flag
  header.writeUInt16LE(METHOD_DEFLATE, 10);
  header.writeUInt16LE(0, 12); // last mod file time
  header.writeUInt16LE(0, 14); // last mod file date
  header.writeUInt32LE(entry.crc, 16);
  header.writeUInt32LE(entry.compressedSize, 20);
  header.writeUInt32LE(entry.uncompressedSize, 24);
  header.writeUInt16LE(entry.nameBuffer.length, 28);
  header.writeUInt16LE(0, 30); // extra field length
  header.writeUInt16LE(0, 32); // file comment length
  header.writeUInt16LE(0, 34); // disk number start
  header.writeUInt16LE(0, 36); // internal file attributes
  header.writeUInt32LE(0, 38); // external file attributes
  header.writeUInt32LE(entry.localHeaderOffset, 42);
  return Buffer.concat([header, entry.nameBuffer]);
}

function writeEndOfCentralDirectory(
  entryCount: number,
  centralDirectorySize: number,
  centralDirectoryOffset: number,
): Buffer {
  const record = Buffer.alloc(22);
  record.writeUInt32LE(END_OF_CENTRAL_DIRECTORY_SIGNATURE, 0);
  record.writeUInt16LE(0, 4); // disk number
  record.writeUInt16LE(0, 6); // disk with central directory
  record.writeUInt16LE(entryCount, 8); // entries on this disk
  record.writeUInt16LE(entryCount, 10); // total entries
  record.writeUInt32LE(centralDirectorySize, 12);
  record.writeUInt32LE(centralDirectoryOffset, 16);
  record.writeUInt16LE(0, 20); // comment length
  return record;
}

/**
 * Builds a ZIP archive buffer in-memory from a map of entry name -> raw
 * file contents. Entry names are written verbatim — no sanitization, no
 * validation — so callers can construct entries with arbitrary names,
 * including path-traversal sequences like `../../etc/passwd`.
 */
export function buildZipBuffer(entries: ZipEntries): Buffer {
  const localParts: Buffer[] = [];
  const builtEntries: BuiltEntry[] = [];
  let offset = 0;

  for (const [name, contents] of Object.entries(entries)) {
    const entry = buildEntry(name, contents, offset);
    const localPart = writeLocalFileHeader(entry);
    localParts.push(localPart, entry.compressed);
    offset += localPart.length + entry.compressed.length;
    builtEntries.push(entry);
  }

  const centralDirectoryOffset = offset;
  const centralParts = builtEntries.map((entry) => writeCentralDirectoryHeader(entry));
  const centralDirectoryBuffer = Buffer.concat(centralParts);

  const endRecord = writeEndOfCentralDirectory(
    builtEntries.length,
    centralDirectoryBuffer.length,
    centralDirectoryOffset,
  );

  return Buffer.concat([...localParts, centralDirectoryBuffer, endRecord]);
}

/**
 * Builds a ZIP archive from a map of entry name -> raw file contents and
 * writes it to `destPath`.
 */
export async function writeZipFile(destPath: string, entries: ZipEntries): Promise<void> {
  const buffer = buildZipBuffer(entries);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- test helper writes to a caller-supplied temp path by design
  await writeFile(destPath, buffer);
}
