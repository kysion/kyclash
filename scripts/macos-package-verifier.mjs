import fs from 'node:fs'

/**
 * The production feature marker is intentionally boring: it is a fixed byte
 * sequence in a dedicated Mach-O section.  Keeping the value here (instead of
 * searching a linker/tool output) lets the package verifier inspect the
 * signed executable itself.
 */
export const PRODUCTION_MARKER_SEGMENT = '__TEXT'
export const PRODUCTION_MARKER_SECTION = '__kyclash_prod'
export const PRODUCTION_MARKER_BYTES = Buffer.from('KYCLASH-PROD-V1\0', 'ascii')

const MH_MAGIC_64 = 0xfeedfacf
const FAT_MAGIC = 0xcafebabe
const FAT_CIGAM = 0xbebafeca
const FAT_MAGIC_64 = 0xcafebabf
const FAT_CIGAM_64 = 0xbfbafeca
const LC_SEGMENT_64 = 0x19
const CPU_TYPE_X86_64 = 0x01000007
const CPU_TYPE_ARM64 = 0x0100000c
const MH_EXECUTE = 0x2
const SECTION_TYPE_MASK = 0x000000ff
const S_REGULAR = 0x0

const ARCH_CPU_TYPES = Object.freeze({
  arm64: CPU_TYPE_ARM64,
  aarch64: CPU_TYPE_ARM64,
  x86_64: CPU_TYPE_X86_64,
  x64: CPU_TYPE_X86_64,
})

const readUInt = (bytes, offset, width, littleEndian) => {
  if (offset < 0 || offset + width > bytes.length) {
    throw new Error(`Mach-O field outside file at offset ${offset}`)
  }
  if (width === 4) {
    return littleEndian
      ? bytes.readUInt32LE(offset)
      : bytes.readUInt32BE(offset)
  }
  if (width === 8) {
    const value = littleEndian
      ? bytes.readBigUInt64LE(offset)
      : bytes.readBigUInt64BE(offset)
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`Mach-O field is too large at offset ${offset}`)
    }
    return Number(value)
  }
  throw new Error(`unsupported Mach-O integer width ${width}`)
}

const readPaddedName = (bytes, offset, width, label) => {
  if (offset < 0 || offset + width > bytes.length) {
    throw new Error(`Mach-O name outside file at offset ${offset}`)
  }
  const window = bytes.subarray(offset, offset + width)
  const terminator = window.indexOf(0)
  if (
    terminator !== -1 &&
    window.subarray(terminator).some((byte) => byte !== 0)
  ) {
    throw new Error(`${label} has non-NUL name padding`)
  }
  return window.toString('ascii', 0, terminator === -1 ? width : terminator)
}

const assertRange = (offset, size, total, label) => {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(size) ||
    offset < 0 ||
    size < 0 ||
    offset > total ||
    size > total - offset
  ) {
    throw new Error(`invalid Mach-O ${label} range`)
  }
}

const assertContainedRange = (offset, size, outerOffset, outerSize, label) => {
  const outerEnd = outerOffset + outerSize
  if (
    !Number.isSafeInteger(outerOffset) ||
    !Number.isSafeInteger(outerSize) ||
    outerOffset < 0 ||
    outerSize < 0 ||
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(size) ||
    !Number.isSafeInteger(outerEnd) ||
    offset < outerOffset ||
    size < 0 ||
    offset > outerEnd ||
    size > outerEnd - offset
  ) {
    throw new Error(`Mach-O ${label} is outside its containing range`)
  }
}

const cpuName = (cpuType) => {
  if (cpuType === CPU_TYPE_ARM64) return 'arm64'
  if (cpuType === CPU_TYPE_X86_64) return 'x86_64'
  return `cpu-${cpuType}`
}

const parseThinSlice = (
  bytes,
  sliceOffset,
  sliceSize,
  sliceIndex,
  littleEndian,
) => {
  assertRange(sliceOffset, sliceSize, bytes.length, `slice ${sliceIndex}`)
  const end = sliceOffset + sliceSize
  const headerSize = 32
  assertRange(sliceOffset, headerSize, end, `slice ${sliceIndex} header`)
  const magic = readUInt(bytes, sliceOffset, 4, littleEndian)
  if (magic !== MH_MAGIC_64) {
    throw new Error(`slice ${sliceIndex} is not a 64-bit Mach-O executable`)
  }
  const cpuType = readUInt(bytes, sliceOffset + 4, 4, littleEndian)
  const cpuSubtype = readUInt(bytes, sliceOffset + 8, 4, littleEndian)
  const fileType = readUInt(bytes, sliceOffset + 12, 4, littleEndian)
  const ncmds = readUInt(bytes, sliceOffset + 16, 4, littleEndian)
  const sizeofcmds = readUInt(bytes, sliceOffset + 20, 4, littleEndian)
  if (fileType !== MH_EXECUTE) {
    throw new Error(`slice ${sliceIndex} is not a Mach-O executable`)
  }
  const loadCommandsOffset = sliceOffset + headerSize
  assertRange(
    loadCommandsOffset,
    sizeofcmds,
    end,
    `slice ${sliceIndex} load commands`,
  )
  if (ncmds > Math.floor(sizeofcmds / 8)) {
    throw new Error(`slice ${sliceIndex} has too many load commands`)
  }

  const sections = []
  let commandOffset = loadCommandsOffset
  for (let commandIndex = 0; commandIndex < ncmds; commandIndex += 1) {
    assertRange(commandOffset, 8, end, `load command ${commandIndex}`)
    const command = readUInt(bytes, commandOffset, 4, littleEndian)
    const commandSize = readUInt(bytes, commandOffset + 4, 4, littleEndian)
    if (
      commandSize < 8 ||
      commandOffset + commandSize > loadCommandsOffset + sizeofcmds
    ) {
      throw new Error(`invalid Mach-O load command ${commandIndex} size`)
    }
    if (command === LC_SEGMENT_64) {
      const segmentMinimumSize = 72
      if (commandSize < segmentMinimumSize) {
        throw new Error(`invalid LC_SEGMENT_64 command ${commandIndex}`)
      }
      const segmentName = readPaddedName(
        bytes,
        commandOffset + 8,
        16,
        `segment ${commandIndex}`,
      )
      const virtualAddress = readUInt(
        bytes,
        commandOffset + 24,
        8,
        littleEndian,
      )
      const virtualSize = readUInt(bytes, commandOffset + 32, 8, littleEndian)
      const fileOffset = readUInt(bytes, commandOffset + 40, 8, littleEndian)
      const fileSize = readUInt(bytes, commandOffset + 48, 8, littleEndian)
      const sectionCount = readUInt(bytes, commandOffset + 64, 4, littleEndian)
      const sectionTableOffset = commandOffset + 72
      const sectionTableSize = sectionCount * 80
      if (
        !Number.isSafeInteger(sectionTableSize) ||
        sectionTableOffset + sectionTableSize > commandOffset + commandSize
      ) {
        throw new Error(
          `invalid section table in LC_SEGMENT_64 command ${commandIndex}`,
        )
      }
      assertRange(
        sliceOffset + fileOffset,
        fileSize,
        end,
        `segment ${segmentName}`,
      )
      for (
        let sectionIndex = 0;
        sectionIndex < sectionCount;
        sectionIndex += 1
      ) {
        const sectionOffset = sectionTableOffset + sectionIndex * 80
        const sectionName = readPaddedName(
          bytes,
          sectionOffset,
          16,
          `section ${sectionIndex}`,
        )
        const sectionSegmentName = readPaddedName(
          bytes,
          sectionOffset + 16,
          16,
          `section ${sectionIndex} segment`,
        )
        if (sectionSegmentName !== segmentName) {
          throw new Error(
            `section ${sectionIndex} segment name does not match its LC_SEGMENT_64`,
          )
        }
        const sectionAddress = readUInt(
          bytes,
          sectionOffset + 32,
          8,
          littleEndian,
        )
        const sectionSize = readUInt(bytes, sectionOffset + 40, 8, littleEndian)
        const sectionFileOffset = readUInt(
          bytes,
          sectionOffset + 48,
          4,
          littleEndian,
        )
        const relocationCount = readUInt(
          bytes,
          sectionOffset + 60,
          4,
          littleEndian,
        )
        const sectionFlags = readUInt(
          bytes,
          sectionOffset + 64,
          4,
          littleEndian,
        )
        assertContainedRange(
          sectionAddress,
          sectionSize,
          virtualAddress,
          virtualSize,
          `section ${sectionIndex} virtual range`,
        )
        if ((sectionFlags & SECTION_TYPE_MASK) === S_REGULAR) {
          assertContainedRange(
            sectionFileOffset,
            sectionSize,
            fileOffset,
            fileSize,
            `section ${sectionIndex} file range`,
          )
        }
        const isTarget =
          sectionSegmentName === PRODUCTION_MARKER_SEGMENT &&
          sectionName === PRODUCTION_MARKER_SECTION
        if (!isTarget) continue
        const absoluteOffset = sliceOffset + sectionFileOffset
        let sectionBytes = null
        let rangeError = null
        try {
          if ((sectionFlags & SECTION_TYPE_MASK) !== S_REGULAR) {
            throw new Error('marker section must not be zerofill')
          }
          if (sectionFlags !== S_REGULAR || relocationCount !== 0) {
            throw new Error('marker section flags or relocations are invalid')
          }
          assertContainedRange(
            sectionFileOffset,
            sectionSize,
            fileOffset,
            fileSize,
            `marker section ${sectionIndex} file range`,
          )
          if (sectionFileOffset < headerSize + sizeofcmds) {
            throw new Error('marker section overlaps Mach-O load commands')
          }
          assertRange(
            absoluteOffset,
            sectionSize,
            end,
            `marker section ${sectionIndex}`,
          )
          sectionBytes = Buffer.from(
            bytes.subarray(absoluteOffset, absoluteOffset + sectionSize),
          )
        } catch (error) {
          rangeError = error instanceof Error ? error.message : String(error)
        }
        sections.push({
          sliceIndex,
          cpuType,
          cpuSubtype,
          architecture: cpuName(cpuType),
          segment: sectionSegmentName,
          section: sectionName,
          size: sectionSize,
          fileOffset: sectionFileOffset,
          address: sectionAddress,
          flags: sectionFlags,
          relocationCount,
          bytes: sectionBytes,
          valid: sectionBytes?.equals(PRODUCTION_MARKER_BYTES) === true,
          rangeError,
        })
      }
    }
    commandOffset += commandSize
  }
  return {
    sliceIndex,
    cpuType,
    cpuSubtype,
    architecture: cpuName(cpuType),
    offset: sliceOffset,
    size: sliceSize,
    markers: sections,
  }
}

const parseFatSlices = (bytes, magic) => {
  const littleEndian = magic === FAT_CIGAM || magic === FAT_CIGAM_64
  const isFat64 = magic === FAT_MAGIC_64 || magic === FAT_CIGAM_64
  const count = readUInt(bytes, 4, 4, littleEndian)
  const entrySize = isFat64 ? 32 : 20
  const tableSize = count * entrySize
  assertRange(8, tableSize, bytes.length, 'fat architecture table')
  const slices = []
  for (let index = 0; index < count; index += 1) {
    const entryOffset = 8 + index * entrySize
    const cpuType = readUInt(bytes, entryOffset, 4, littleEndian)
    const cpuSubtype = readUInt(bytes, entryOffset + 4, 4, littleEndian)
    const offset = readUInt(
      bytes,
      entryOffset + 8,
      isFat64 ? 8 : 4,
      littleEndian,
    )
    const size = readUInt(
      bytes,
      entryOffset + (isFat64 ? 16 : 12),
      isFat64 ? 8 : 4,
      littleEndian,
    )
    assertRange(offset, size, bytes.length, `fat slice ${index}`)
    // parseThinSlice validates the embedded Mach-O header and uses the
    // architecture from that header as the authoritative value.
    const embeddedMagicBE = bytes.readUInt32BE(offset)
    const embeddedMagicLE = bytes.readUInt32LE(offset)
    const embeddedLittleEndian = embeddedMagicLE === MH_MAGIC_64
    if (embeddedMagicBE !== MH_MAGIC_64 && !embeddedLittleEndian) {
      throw new Error(`fat slice ${index} is not a 64-bit Mach-O executable`)
    }
    const slice = parseThinSlice(
      bytes,
      offset,
      size,
      index,
      embeddedLittleEndian,
    )
    if (slice.cpuType !== cpuType || slice.cpuSubtype !== cpuSubtype) {
      throw new Error(`fat slice ${index} header architecture mismatch`)
    }
    slices.push(slice)
  }
  return slices
}

/**
 * Parse a signed Mach-O executable without relying on `strings`, `otool`, or
 * linker diagnostics.  Every matching section is returned, including malformed
 * or wrong-byte sections, so callers can fail closed on forged markers.
 */
export const inspectMachOMarkers = (
  fileOrBytes,
  { targetArch = 'arm64' } = {},
) => {
  const bytes = Buffer.isBuffer(fileOrBytes)
    ? fileOrBytes
    : fs.readFileSync(fileOrBytes)
  if (bytes.length < 4) throw new Error('Mach-O executable is truncated')
  const magicBE = bytes.readUInt32BE(0)
  let slices
  if (
    magicBE === FAT_MAGIC ||
    magicBE === FAT_CIGAM ||
    magicBE === FAT_MAGIC_64 ||
    magicBE === FAT_CIGAM_64
  ) {
    slices = parseFatSlices(bytes, magicBE)
  } else {
    const magicLE = bytes.readUInt32LE(0)
    if (magicLE === MH_MAGIC_64) {
      slices = [parseThinSlice(bytes, 0, bytes.length, 0, true)]
    } else if (magicBE === MH_MAGIC_64) {
      slices = [parseThinSlice(bytes, 0, bytes.length, 0, false)]
    } else {
      throw new Error('unsupported or malformed Mach-O magic')
    }
  }
  const expectedCpuType =
    ARCH_CPU_TYPES[targetArch] ??
    ARCH_CPU_TYPES[String(targetArch).replace(/-apple-darwin$/, '')]
  if (!expectedCpuType)
    throw new Error(`unsupported target architecture: ${targetArch}`)
  const selectedSlices = slices.filter(
    (slice) => slice.cpuType === expectedCpuType,
  )
  if (selectedSlices.length !== 1) {
    throw new Error(
      `expected exactly one ${targetArch} Mach-O slice, found ${selectedSlices.length}`,
    )
  }
  return {
    targetArch,
    slices,
    selectedSlice: selectedSlices[0],
    markers: slices.flatMap((slice) => slice.markers),
    selectedMarkers: selectedSlices[0].markers,
  }
}

/**
 * Apply the closed marker policy used by package verification.  The ordinary
 * release profile rejects even a malformed marker section; the VM-lab profile
 * requires one exact marker and rejects hidden markers in another fat slice.
 */
export const assertProductionCompileMarker = (
  fileOrBytes,
  { profile = 'release-default', targetArch = 'arm64' } = {},
) => {
  const inspection = inspectMachOMarkers(fileOrBytes, { targetArch })
  if (profile === 'release-default') {
    if (inspection.markers.length !== 0) {
      throw new Error(
        `release-default package must not contain ${PRODUCTION_MARKER_SEGMENT},${PRODUCTION_MARKER_SECTION}`,
      )
    }
    return inspection
  }
  if (profile !== 'networking-production-vm-lab') {
    throw new Error(`unknown package verifier profile: ${profile}`)
  }
  if (
    inspection.markers.length !== 1 ||
    inspection.selectedMarkers.length !== 1
  ) {
    throw new Error(
      'networking-production-vm-lab package must contain exactly one compile marker',
    )
  }
  if (
    targetArch !== 'arm64' &&
    targetArch !== 'aarch64' &&
    targetArch !== 'aarch64-apple-darwin'
  ) {
    throw new Error('networking-production-vm-lab requires arm64')
  }
  if (
    inspection.slices.length !== 1 ||
    inspection.selectedSlice.cpuType !== CPU_TYPE_ARM64
  ) {
    throw new Error(
      'networking-production-vm-lab executable must be arm64-only',
    )
  }
  const [marker] = inspection.selectedMarkers
  if (!marker.valid) {
    throw new Error(
      'networking-production-vm-lab compile marker bytes are invalid',
    )
  }
  return inspection
}

export const targetArchitectureFromTriple = (target) => {
  if (target === 'aarch64-apple-darwin') return 'arm64'
  if (target === 'x86_64-apple-darwin') return 'x86_64'
  throw new Error(`unsupported macOS target: ${target}`)
}
